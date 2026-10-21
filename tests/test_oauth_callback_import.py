"""A server-side Docker deployment can import OAuth without a local listener."""

import json
import shutil
import subprocess
import time
from unittest.mock import AsyncMock, Mock
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient as AnonymousClient

from src import admin_auth, main
from src.oauth_callback import parse_callback_url
from tests.admin_client import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(
        main.app.state, "admin_auth", admin_auth.AdminAuth("test-password-very-long")
    )
    monkeypatch.setattr(main, "API_KEYS", ["model-key"])
    with TestClient(main.app) as client:
        yield client


def callback(client, **extra):
    state = client.post("/api/admin/oauth-state").json()["state"]
    params = {
        "loginTraceID": state,
        "userJwt": json.dumps({"Token": "synthetic-token", "RefreshToken": "synthetic-refresh"}),
        "userInfo": json.dumps({"UserID": "synthetic-user", "ScreenName": "测试用户"}),
        **extra,
    }
    return f"http://127.0.0.1:{main.LOCAL_LISTENER_PORT}/authorize?{urlencode(params)}"


def test_pasted_callback_imports_account_without_visiting_loopback(client, monkeypatch):
    add = Mock(return_value="synthetic-user")
    monkeypatch.setattr(main.auth, "add_account", add)
    url = callback(client)
    response = client.post("/api/admin/oauth-import", json={"callback_url": url})
    assert response.status_code == 200
    assert response.json() == {"success": True, "account_id": "synthetic-user"}
    assert response.headers["cache-control"] == "no-store"
    assert "synthetic-refresh" not in response.text
    record = add.call_args.args[0]
    assert record["token"] == "synthetic-token"
    assert record["refresh_token"] == "synthetic-refresh"
    assert record["screen_name"] == "测试用户"
    assert client.post("/api/admin/oauth-import", json={"callback_url": url}).status_code == 403
    add.assert_called_once()


def test_refresh_only_callback_uses_existing_server_exchange(client, monkeypatch):
    exchange = AsyncMock(return_value={"token": "exchanged-token", "user_id": "synthetic-user"})
    monkeypatch.setattr(main, "_exchange_refresh_token", exchange)
    add = Mock(return_value="synthetic-user")
    monkeypatch.setattr(main.auth, "add_account", add)
    url = callback(client, userJwt="", refreshToken="synthetic-refresh", host="https://api.trae.cn")
    response = client.post("/api/admin/oauth-import", json={"callback_url": url})
    assert response.status_code == 200
    exchange.assert_awaited_once()
    assert add.call_args.args[0]["token"] == "exchanged-token"


def test_import_requires_admin_csrf_and_owner_session(client, monkeypatch):
    url = callback(client)
    parsed = AsyncMock(return_value={"token": "synthetic"})
    monkeypatch.setattr(main, "_parse_oauth_params", parsed)
    with AnonymousClient(main.app) as anonymous:
        assert (
            anonymous.post(
                "/api/admin/oauth-import",
                json={"callback_url": url},
                headers={"Authorization": "Bearer model-key"},
            ).status_code
            == 401
        )
    with TestClient(main.app) as other_admin:
        assert (
            other_admin.post("/api/admin/oauth-import", json={"callback_url": url}).status_code
            == 403
        )
    client.headers.pop("x-admin-csrf")
    assert client.post("/api/admin/oauth-import", json={"callback_url": url}).status_code == 403
    parsed.assert_not_awaited()


def test_expired_and_invalid_callbacks_never_reach_exchange(client, monkeypatch):
    url = callback(client)
    parsed = AsyncMock()
    monkeypatch.setattr(main, "_parse_oauth_params", parsed)
    for session in main.app.state.admin_auth.sessions.values():
        session.grants = {key: time.monotonic() - 1 for key in session.grants}
    assert client.post("/api/admin/oauth-import", json={"callback_url": url}).status_code == 403
    assert (
        client.post(
            "/api/admin/oauth-import",
            json={"callback_url": "https://attacker.example/authorize?refreshToken=secret"},
        ).status_code
        == 400
    )
    parsed.assert_not_awaited()


@pytest.mark.parametrize(
    "url",
    [
        "",
        None,
        [],
        "https://127.0.0.1:8765/authorize?loginTraceID=x",
        "http://127.0.0.1:8766/authorize?loginTraceID=x",
        "http://127.0.0.1:8765/other?loginTraceID=x",
        "http://localhost:8765/authorize?loginTraceID=x",
        "http://127.0.0.1:8765@attacker.example/authorize?loginTraceID=x",
        "http://user@127.0.0.1:8765/authorize?loginTraceID=x",
        "http://127.0.0.1:8765/authorize?loginTraceID=x#fragment",
        "http://127.0.0.1:8765/authorize?loginTraceID=x&loginTraceID=x",
        "http://127.0.0.1:8765/authorize?loginTraceID=x&login_trace_id=y",
        "http://127.0.0.1:8765/authorize?userJwt=x",
        "http://127.0.0.1:8765/authorize?loginTraceID=x\ny",
        "http://127.0.0.1:8765/authorize?loginTraceID=x&" + "&".join(f"p{i}=x" for i in range(65)),
        "x" * 65537,
    ],
)
def test_parser_rejects_non_callback_urls(url):
    with pytest.raises(ValueError):
        parse_callback_url(url, 8765)


def test_bad_json_or_credentials_do_not_echo_pasted_secrets(client, monkeypatch):
    assert client.post("/api/admin/oauth-import", json=[]).status_code == 400
    response = client.post(
        "/api/admin/oauth-import",
        content=b'{"secret":"sensitive-value"',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert "sensitive-value" not in response.text
    monkeypatch.setattr(main, "_parse_oauth_params", AsyncMock(return_value={}))
    response = client.post("/api/admin/oauth-import", json={"callback_url": callback(client)})
    assert response.status_code == 400
    assert "synthetic-token" not in response.text


def test_default_authorization_opens_popup_without_checking_for_helper(client, tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js unavailable")
    page = client.get("/web/login").text
    assert 'id="callback-url"' in page
    source = page[page.index("async function startAuth()") : page.index("let usageRefreshing")]
    script = tmp_path / "start-auth.js"
    script.write_text(
        "const vm=require('node:vm'),assert=require('node:assert/strict');\n"
        "const popup={location:{},closed:false,close(){this.closed=true}};const nodes={};\n"
        "const context={state:{},window:{open:()=>popup},document:{getElementById:id=>"
        "(nodes[id]||=( {style:{},disabled:false}))},checkLocalListener:()=>{throw Error('helper must not be required')},"
        "postJSON:async url=>{assert.equal(url,'/api/admin/oauth-state');return {success:true,state:'one-use-state'}},"
        "buildAuthUrl:async()=>{assert.equal(context.state.traceId,'one-use-state');return 'https://www.trae.cn/authorization'},"
        "setInterval:()=>1,showMsg:()=>{throw Error('unexpected error')}};\n"
        "vm.runInNewContext(" + json.dumps(source) + ",context);\n"
        "context.startAuth().then(()=>{assert.equal(popup.location.href,'https://www.trae.cn/authorization');"
        "assert.equal(context.state.win,popup)}).catch(error=>{console.error(error);process.exit(1)});\n"
    )
    subprocess.run([node, str(script)], check=True, capture_output=True)
