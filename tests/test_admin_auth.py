"""Exercise the real HTTP authentication boundary without seeded cookies."""

from __future__ import annotations

import re
import time
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

from src import admin_auth, main

PASSWORD = "test-admin-password-very-long"


@pytest.fixture
def service(monkeypatch):
    instance = admin_auth.AdminAuth(PASSWORD)
    monkeypatch.setattr(main.app.state, "admin_auth", instance)
    monkeypatch.setattr(main, "API_KEYS", ["model-key"])
    return instance


@pytest.fixture
def client(service):
    with TestClient(main.app, follow_redirects=False) as client:
        yield client


def login(client):
    response = client.post("/api/admin/login", json={"password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"X-Admin-CSRF": response.json()["csrf_token"]}


@pytest.mark.parametrize(
    "path,method",
    [
        ("/web/login", "get"),
        ("/web/login/helper-info", "get"),
        ("/api/accounts", "get"),
        ("/api/accounts/switch", "post"),
        ("/api/accounts/remove", "post"),
        ("/api/accounts/model-enabled", "post"),
        ("/api/settings", "post"),
        ("/api/logout", "post"),
        ("/api/polling", "post"),
        ("/api/checkin/claim-all", "post"),
        ("/api/auto-checkin/run", "post"),
        ("/api/usage/records", "get"),
        ("/api/overview", "get"),
        ("/api/model-test", "post"),
        ("/api/web-auth", "post"),
        ("/authorize", "get"),
        ("/v1/status", "get"),
        ("/docs", "get"),
        ("/openapi.json", "get"),
        ("/api/future-admin-operation", "post"),
    ],
)
def test_anonymous_and_model_keys_cannot_access_management(client, path, method):
    for headers in ({}, {"Authorization": "Bearer model-key"}, {"x-api-key": "model-key"}):
        response = getattr(client, method)(path, headers=headers)
        assert response.status_code == (303 if path == "/web/login" else 401)
        assert response.headers["cache-control"] == "no-store"


def test_missing_configuration_fails_closed_even_without_model_keys(client, monkeypatch):
    monkeypatch.setattr(main.app.state, "admin_auth", admin_auth.AdminAuth(""))
    monkeypatch.setattr(main, "API_KEYS", [])
    assert client.get("/api/accounts").status_code == 503
    assert client.post("/api/web-auth", json={"token": "synthetic"}).status_code == 503
    assert client.post("/api/admin/login", json={"password": PASSWORD}).status_code == 503
    page = client.get("/admin/login")
    assert page.status_code == 200
    assert "RELAY_ADMIN_PASSWORD" in page.text
    assert 'type="submit" disabled' in page.text
    assert client.get("/healthz").status_code == 200
    assert client.get("/web/login").status_code == 303


def test_login_sets_hardened_cookie_and_console_has_csrf(client, service):
    csrf = login(client)
    cookie = client.cookies.get(admin_auth.COOKIE)
    assert len(cookie) >= 43
    assert cookie not in service.sessions  # Server retains a hash only.
    assert service.verifier != PASSWORD.encode()
    response = client.get("/api/admin/session")
    assert response.json()["csrf_token"] == csrf["X-Admin-CSRF"]
    page = client.get("/web/login")
    assert page.status_code == 200
    assert f'<meta name="admin-csrf" content="{csrf["X-Admin-CSRF"]}">' in page.text
    assert "退出管理" in page.text
    assert PASSWORD not in page.text
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["referrer-policy"] == "no-referrer"
    assert client.get("/admin/login").status_code == 303


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_cookie_flags(service, scheme):
    with TestClient(main.app, base_url=f"{scheme}://testserver") as client:
        response = client.post("/api/admin/login", json={"password": PASSWORD})
        cookie = response.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=lax" in cookie
        assert "max-age=43200" in cookie
        assert ("secure" in cookie) == (scheme == "https")


def test_explicit_secure_cookie(service):
    service.secure_cookie = True
    with TestClient(main.app) as client:
        response = client.post("/api/admin/login", json={"password": PASSWORD})
        assert "Secure" in response.headers["set-cookie"]


def test_wrong_password_rate_limit_and_forwarded_headers_cannot_bypass(client):
    for attempt in range(5):
        response = client.post(
            "/api/admin/login",
            json={"password": "wrong"},
            headers={"X-Forwarded-For": f"8.8.8.{attempt}"},
        )
        assert response.status_code == 401
    response = client.post("/api/admin/login", json={"password": PASSWORD})
    assert response.status_code == 429
    assert response.headers["retry-after"] == "300"
    assert admin_auth.COOKIE not in client.cookies


def test_global_rate_limit_and_window_expiry(service, monkeypatch):
    monkeypatch.setattr(admin_auth.time, "monotonic", lambda: 1000.0)
    for index in range(100):
        assert service.allow_attempt(str(index))
    assert not service.allow_attempt("different-host")
    monkeypatch.setattr(admin_auth.time, "monotonic", lambda: 1301.0)
    assert service.allow_attempt("different-host")


def test_login_rejects_cross_origin_simple_forms_and_bad_bodies(client):
    assert (
        client.post(
            "/api/admin/login",
            json={"password": PASSWORD},
            headers={"Origin": "https://attacker.example"},
        ).status_code
        == 403
    )
    assert client.post("/api/admin/login", data={"password": PASSWORD}).status_code == 403
    assert (
        client.post(
            "/api/admin/login",
            json={"password": PASSWORD},
            headers={"Sec-Fetch-Site": "cross-site"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/admin/login", content=b"x" * 5000, headers={"Content-Type": "application/json"}
        ).status_code
        == 413
    )
    assert client.post("/api/admin/login", json=[]).status_code == 400
    assert client.post("/api/admin/login", json={"password": 123}).status_code == 400


def test_csrf_blocks_writes_before_handler_and_allows_valid_request(client, monkeypatch):
    headers = login(client)
    remove = Mock(return_value=True)
    monkeypatch.setattr(main.auth, "remove_account", remove)
    for extra in (
        {},
        {"X-Admin-CSRF": "wrong"},
        {**headers, "Origin": "http://attacker.testserver"},
        {**headers, "Sec-Fetch-Site": "cross-site"},
    ):
        response = client.post("/api/accounts/remove", json={"id": "target"}, headers=extra)
        assert response.status_code == 403
    remove.assert_not_called()
    response = client.post(
        "/api/accounts/remove",
        json={"id": "target"},
        headers={**headers, "Origin": "http://testserver"},
    )
    assert response.status_code == 200
    remove.assert_called_once_with("target")


def test_expired_forged_and_revoked_sessions_are_rejected(client, service):
    headers = login(client)
    old_cookie = client.cookies.get(admin_auth.COOKIE)
    assert client.post("/api/admin/logout", headers=headers).status_code == 200
    assert client.get("/api/accounts").status_code == 401
    client.cookies.set(admin_auth.COOKIE, old_cookie)
    assert client.get("/api/accounts").status_code == 401
    client.cookies.clear()
    login(client)
    for session in service.sessions.values():
        session.expires = time.monotonic() - 1
    assert client.get("/api/accounts").status_code == 401
    client.cookies.set(admin_auth.COOKIE, "forged-session")
    assert client.get("/api/accounts").status_code == 401


def test_login_rotates_session_and_restart_revokes_old_sessions(client, monkeypatch):
    login(client)
    old_cookie = client.cookies.get(admin_auth.COOKIE)
    login(client)
    assert client.cookies.get(admin_auth.COOKIE) != old_cookie
    client.cookies.clear()
    client.cookies.set(admin_auth.COOKIE, old_cookie)
    assert client.get("/api/accounts").status_code == 401
    monkeypatch.setattr(main.app.state, "admin_auth", admin_auth.AdminAuth(PASSWORD))
    assert client.get("/api/accounts").status_code == 401


def test_model_ingress_still_requires_api_key_even_for_administrator(client, monkeypatch):
    login(client)
    assert client.post("/v1/chat/completions", json={}).status_code == 401
    assert client.post("/api/agent/v3/custom_model_proxy/chat", json={}).status_code == 401
    dispatch = AsyncMock(return_value=main.JSONResponse({"model": "ok"}))
    monkeypatch.setattr(main, "handle_chat", dispatch)
    response = client.post("/v1/chat/completions", json={}, headers={"x-api-key": "model-key"})
    assert response.status_code == 200
    dispatch.assert_awaited_once()


def test_public_endpoints_and_helper_never_contain_admin_secrets(client):
    for path in ("/healthz", "/favicon.svg", "/v1/models", "/web/login/download?as=py"):
        response = client.get(path)
        assert response.status_code == 200
        assert PASSWORD not in response.text
    assert 'name="password"' in client.get("/admin/login").text


def test_helper_import_grant_is_scoped_single_use_and_not_an_admin_session(client, monkeypatch):
    headers = login(client)
    grant = client.post("/api/admin/oauth-state", headers=headers).json()["state"]
    add_account = Mock()
    monkeypatch.setattr(main.auth, "add_account", add_account)
    # A separate client models the local helper, which holds no admin cookie.
    with TestClient(main.app) as helper:
        ticket_headers = {admin_auth.IMPORT_HEADER: grant}
        assert helper.get("/api/accounts", headers=ticket_headers).status_code == 401
        assert helper.post("/api/settings", headers=ticket_headers).status_code == 401
        response = helper.post("/api/web-auth", json={"token": "synthetic"}, headers=ticket_headers)
        assert response.status_code == 200
        assert (
            helper.post(
                "/api/web-auth", json={"token": "synthetic"}, headers=ticket_headers
            ).status_code
            == 401
        )
    add_account.assert_called_once()


@pytest.mark.parametrize("invalidate", ["expire_grant", "expire_session", "logout"])
def test_helper_grant_expires_and_is_revoked_with_session(client, service, invalidate):
    headers = login(client)
    grant = client.post("/api/admin/oauth-state", headers=headers).json()["state"]
    session = next(iter(service.sessions.values()))
    if invalidate == "expire_grant":
        session.grants = {key: 0 for key in session.grants}
    elif invalidate == "expire_session":
        session.expires = 0
    else:
        client.post("/api/admin/logout", headers=headers)
    with TestClient(main.app) as helper:
        assert (
            helper.post(
                "/api/web-auth",
                json={"token": "synthetic"},
                headers={admin_auth.IMPORT_HEADER: grant},
            ).status_code
            == 401
        )


def test_direct_oauth_callback_requires_owner_and_state_and_rejects_replay(client, monkeypatch):
    headers = login(client)
    grant = client.post("/api/admin/oauth-state", headers=headers).json()["state"]
    parsed = AsyncMock(return_value={"token": "synthetic"})
    add = Mock()
    monkeypatch.setattr(main, "_parse_oauth_params", parsed)
    monkeypatch.setattr(main.auth, "add_account", add)
    assert client.get("/authorize").status_code == 403
    with TestClient(main.app) as other:
        login(other)
        assert other.get("/authorize", params={"login_trace_id": grant}).status_code == 403
    parsed.assert_not_awaited()
    assert client.get("/authorize", params={"login_trace_id": grant}).status_code == 200
    assert client.get("/authorize", params={"login_trace_id": grant}).status_code == 403
    add.assert_called_once()


def test_password_file_precedence_and_unreadable_file_lockout(tmp_path, monkeypatch):
    password_file = tmp_path / "password"
    password_file.write_text(PASSWORD + "\n")
    monkeypatch.setenv("RELAY_ADMIN_PASSWORD", "different-password")
    monkeypatch.setenv("RELAY_ADMIN_PASSWORD_FILE", str(password_file))
    service = admin_auth.AdminAuth.from_env()
    assert service.verify(PASSWORD)
    assert not service.verify("different-password")
    password_file.unlink()
    assert not admin_auth.AdminAuth.from_env().configured


def test_console_and_login_javascript_parse(client, tmp_path):
    import shutil
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js unavailable")
    login_html = client.get("/admin/login").text
    login(client)
    for page in (login_html, client.get("/web/login").text):
        for index, script in enumerate(re.findall(r"<script>(.*?)</script>", page, re.DOTALL)):
            path = tmp_path / f"script-{index}.js"
            path.write_text(script)
            subprocess.run([node, "--check", str(path)], check=True, capture_output=True)


def test_browser_fetch_sends_csrf_only_to_relay_and_redirects_expired_sessions(client, tmp_path):
    import json
    import shutil
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js unavailable")
    login(client)
    page = client.get("/web/login").text
    wrapper = page[page.index("const adminFetch=") : page.index("function applyTheme(")]
    script = tmp_path / "fetch-boundary.js"
    script.write_text(
        "const assert=require('node:assert/strict'),vm=require('node:vm');\n"
        "const calls=[],redirects=[];let status=200;\n"
        "const context={URL,Headers,Request,document:{querySelector:()=>({content:'csrf-test'})},"
        "location:{origin:'https://relay.example',href:'https://relay.example/web/login',"
        "replace:url=>redirects.push(url)},window:{fetch:async(url,opts)=>{"
        "calls.push({url,opts});return {status};}}};\n"
        "vm.runInNewContext(" + json.dumps(wrapper) + ",context);\n"
        "(async()=>{\n"
        "await context.window.fetch('/api/settings',{method:'POST'});\n"
        "assert.equal(calls[0].opts.headers.get('X-Admin-CSRF'),'csrf-test');\n"
        "await context.window.fetch('http://127.0.0.1:8765/healthz');\n"
        "assert.equal(calls[1].opts.headers,undefined);\n"
        "status=401;await context.window.fetch('/api/overview');\n"
        "assert.deepEqual(redirects,['/admin/login']);\n"
        "await context.window.fetch('http://127.0.0.1:8765/healthz');\n"
        "assert.equal(redirects.length,1);\n"
        "})().catch(error=>{console.error(error);process.exit(1)});\n"
    )
    subprocess.run([node, str(script)], check=True, capture_output=True)
