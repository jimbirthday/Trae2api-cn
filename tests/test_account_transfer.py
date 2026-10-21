"""Real account backup round trips, persistence and administrator boundaries."""

from __future__ import annotations

import base64
import copy
import json
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient as AnonymousClient

from src import account_transfer, admin_auth, auth, main
from tests.admin_client import TestClient


def record(user_id="user-1", **changes):
    return {
        "user_id": user_id,
        "label": "测试账号 " + user_id,
        "token": f"header.{user_id}{'x' * 140}.signature",
        "refresh_token": "synthetic-refresh-" + user_id,
        "expired_at": "2099-01-01T00:00:00Z",
        "provider_specific": {"webId": user_id, "screenName": "测试账号"},
        "model_enabled": False,
        **changes,
    }


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(main.app.state, "admin_auth", admin_auth.AdminAuth("test-transfer-password"))
    monkeypatch.setattr(auth, "_accounts", {})
    monkeypatch.setattr(auth, "_active_account", "")
    monkeypatch.setattr(auth, "_auth", auth.AuthState())
    monkeypatch.setattr(auth, "_settings", {"upstream_mode": "remote"})
    monkeypatch.setattr(auth, "_poll_enabled", True)
    monkeypatch.setattr(auth, "_polling_mode", "credit-priority")
    monkeypatch.setattr(auth, "_rotation_cursor", 2)
    monkeypatch.setattr(auth, "ACCOUNTS_PATH", tmp_path / "accounts.json")
    monkeypatch.setattr(auth, "_save_env_snapshot", Mock())
    client = TestClient(main.app)
    yield client
    client.close()


def test_export_import_round_trip_restores_credentials_and_new_account_flags(client, monkeypatch):
    records = [record(), record("user-2", model_enabled=True)]
    result = client.post("/api/accounts/import", json=records)
    assert result.json() == {"success": True, "added": 2, "updated": 0, "skipped": 0, "total": 2}
    assert auth.get_active_account_id() == "user-2"  # Prefer a model-enabled account.
    auth._accounts["user-1"]["checkin"] = {"credits": 123, "checked_in": True}
    response = client.post("/api/accounts/export")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "attachment;" in response.headers["content-disposition"]
    backup = response.json()
    assert backup["format"] == account_transfer.FORMAT
    assert "checkin" not in backup["accounts"][0]
    assert "settings" not in backup
    assert backup["accounts"][0]["refresh_token"] == records[0]["refresh_token"]
    monkeypatch.setattr(auth, "_accounts", {})
    monkeypatch.setattr(auth, "_active_account", "")
    result = client.post("/api/accounts/import", json={"data": backup})
    assert result.json()["added"] == 2
    for original in records:
        restored = auth.get_account_record(original["user_id"])
        for key, value in original.items():
            assert restored[key] == value
    persisted = json.loads(auth.ACCOUNTS_PATH.read_text())
    assert persisted["accounts"] == auth._accounts
    assert persisted["poll_enabled"] is True
    assert persisted["polling_mode"] == "credit-priority"
    assert persisted["rotation_cursor"] == 2
    assert persisted["settings"] == {"upstream_mode": "remote"}


def test_duplicates_skip_by_default_and_update_preserves_existing_preferences(client):
    client.post("/api/accounts/import", json=[record()])
    auth._accounts["user-1"]["checkin"] = {"checked_in": True}
    incoming = record(token="updated-synthetic-token", model_enabled=True)
    response = client.post("/api/accounts/import", json=[incoming, incoming, record("user-2")])
    assert response.json()["skipped"] == 2
    assert auth.get_account_record("user-1")["token"] != incoming["token"]
    active = auth.get_active_account_id()
    response = client.post(
        "/api/accounts/import", json={"data": [incoming, incoming], "update_existing": True}
    )
    assert response.json() == {"success": True, "added": 0, "updated": 1, "skipped": 1, "total": 2}
    saved = auth.get_account_record("user-1")
    assert saved["token"] == incoming["token"]
    assert saved["model_enabled"] is False
    assert saved["checkin"] == {"checked_in": True}
    assert auth.get_active_account_id() == active
    assert auth.get_auth().token == incoming["token"]


def test_legacy_store_and_camel_case_fields(client):
    payload = {
        "accounts": {
            "legacy": {
                "Token": "synthetic-token",
                "refreshToken": "synthetic-refresh",
                "clientId": "synthetic-client",
                "expiredAt": 2000000000000,
            }
        },
        "active": "untrusted",
        "poll_enabled": False,
        "settings": {"upstream_mode": "attacker"},
    }
    assert client.post("/api/accounts/import", json=payload).status_code == 200
    saved = auth.get_account_record("legacy")
    assert saved["token"] == "synthetic-token"
    assert saved["client_id"] == "synthetic-client"
    assert saved["expired_at"] == "2000000000000"
    assert auth._settings == {"upstream_mode": "remote"}
    assert auth._poll_enabled is True


def jwt(claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + payload + ".synthetic-signature"


def test_external_account_pool_format_and_reimport(client):
    def external(user_id, enabled):
        return {
            "name": "账号 " + user_id,
            "token": jwt({"data": {"id": user_id, "tenant_id": "synthetic-tenant"}, "exp": 2000000000}),
            "refreshToken": "synthetic-refresh-" + user_id,
            "deviceId": "synthetic-device",
            "machineId": "synthetic-machine",
            "enabled": enabled,
            "cookies": [{"name": "sessionid", "value": "synthetic-cookie-secret"}],
        }

    payload = {"accounts": [external("101", False), external("102", True)]}
    result = client.post("/api/accounts/import", json=payload)
    assert result.json()["added"] == 2
    saved = auth.get_account_record("101")
    assert saved["user_id"] == "101"
    assert saved["label"] == "账号 101"
    assert saved["model_enabled"] is False
    assert saved["refresh_token"] == "synthetic-refresh-101"
    assert saved["expired_at"] == "2000000000"
    assert saved["provider_specific"] == {
        "deviceId": "synthetic-device", "machineId": "synthetic-machine", "tenantId": "synthetic-tenant"
    }
    assert "cookies" not in saved
    exported = client.post("/api/accounts/export")
    assert "synthetic-cookie-secret" not in exported.text
    assert len(exported.json()["accounts"]) == 2
    payload["accounts"][0]["token"] = jwt({"data": {"id": "101"}, "exp": 2100000000})
    assert client.post("/api/accounts/import", json=payload).json()["skipped"] == 2
    assert client.post(
        "/api/accounts/import", json={"data": payload, "update_existing": True}
    ).json()["updated"] == 2
    assert len(auth._accounts) == 2
    assert auth.get_account_record("101")["expired_at"] == "2100000000"


def test_shared_token_prefix_uses_distinct_fingerprints_without_jwt_id(client):
    tokens = [jwt({"sub": "one"}), jwt({"sub": "two"})]
    assert tokens[0][:24] == tokens[1][:24]
    rows = [{"token": token} for token in tokens]
    assert client.post("/api/accounts/import", json=rows).json()["added"] == 2
    assert client.post("/api/accounts/import", json=rows).json()["skipped"] == 2
    assert all(key.startswith("token-") for key in auth._accounts)


def test_explicit_backup_identity_and_preferences_override_jwt_metadata(client):
    row = record(
        token=jwt({"data": {"id": "jwt-user", "tenant_id": "jwt-tenant"}, "exp": 1000}),
        name="Ignored name", enabled=True, provider_specific={"tenantId": "explicit-tenant"},
    )
    assert client.post("/api/accounts/import", json=[row]).status_code == 200
    saved = auth.get_account_record("user-1")
    assert saved["label"] == row["label"]
    assert saved["expired_at"] == row["expired_at"]
    assert saved["model_enabled"] is False
    assert saved["provider_specific"]["tenantId"] == "explicit-tenant"


@pytest.mark.parametrize("claims", [None, [], {"data": []}, {"exp": 10**100}, {"exp": "later"}])
def test_jwt_metadata_is_optional_and_tolerates_invalid_claim_shapes(claims):
    rows = account_transfer.normalize_accounts([{"token": jwt(claims)}])
    assert len(rows) == 1
    assert rows[0][0].startswith("token-")


@pytest.mark.parametrize(
    "invalid",
    [
        None, [], {}, [None], [{"token": 123}], [{"token": ""}],
        [record(provider_specific=[])], [record(model_enabled="false")],
        [record(user_id="bad\nidentifier")],
        [record(token="synthetic\nRELAY_ADMIN_PASSWORD=injected")],
        [record(provider_specific={"webId": "synthetic\nRELAY_ADMIN_PASSWORD=injected"})],
        [record(source="unsupported-source")],
        [{"token": "synthetic", "enabled": "false"}],
        [{"token": "synthetic", "deviceId": "bad\nvalue"}],
        {"accounts": [record()], "version": 2},
        {"data": [record()], "update_existing": "yes"},
    ],
)
def test_invalid_files_never_mutate_store_or_leak_credentials(client, invalid):
    response = client.post("/api/accounts/import", json=invalid)
    assert response.status_code == 400
    assert "synthetic-refresh" not in response.text
    assert auth._accounts == {}
    assert not auth.ACCOUNTS_PATH.exists()


def test_late_invalid_row_and_write_failure_leave_store_unchanged(client, monkeypatch):
    client.post("/api/accounts/import", json=[record()])
    before = copy.deepcopy(auth._accounts)
    saved = auth.ACCOUNTS_PATH.read_bytes()
    response = client.post("/api/accounts/import", json=[record("new"), {"token": []}])
    assert response.status_code == 400
    assert auth._accounts == before
    monkeypatch.setattr(auth.os, "replace", Mock(side_effect=PermissionError("synthetic-secret")))
    response = client.post("/api/accounts/import", json=[record("new")])
    assert response.status_code == 500
    assert "synthetic-secret" not in response.text
    assert auth._accounts == before
    assert auth.ACCOUNTS_PATH.read_bytes() == saved
    assert list(auth.ACCOUNTS_PATH.parent.glob(".accounts-*.tmp")) == []


def test_request_limits_and_malformed_json(client, monkeypatch):
    monkeypatch.setattr(account_transfer, "MAX_BYTES", 1024)
    response = client.post("/api/accounts/import", content=b" " * 1025)
    assert response.status_code == 413
    response = client.post("/api/accounts/import", content=b'{"token":"secret"')
    assert response.status_code == 400
    assert "secret" not in response.text
    monkeypatch.setattr(account_transfer, "MAX_ACCOUNTS", 1)
    assert client.post("/api/accounts/import", json=[record(), record("two")]).status_code == 400
    assert auth._accounts == {}


@pytest.mark.parametrize("path", ["/api/accounts/import", "/api/accounts/export"])
def test_transfer_requires_administrator_session_and_csrf(client, path):
    with AnonymousClient(main.app) as anonymous:
        response = anonymous.post(path, json=[], headers={"x-api-key": "model-key"})
        assert response.status_code == 401
    client.headers.pop(admin_auth.CSRF_HEADER)
    assert client.post(path, json=[]).status_code == 403


def test_imported_labels_and_identifiers_are_safe_in_console(client):
    identifier = "user');window.injected=true;//"
    response = client.post(
        "/api/accounts/import", json=[record(identifier, label="<img src=x onerror=alert(1)>")]
    )
    assert response.status_code == 200
    page = client.get("/web/login").text
    assert "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "onclick=\"removeAccount(&quot;user&#x27;);window.injected=true;//&quot;)\"" in page
    assert 'id="account-transfer"' in page
    assert 'id="account-import-file"' in page
