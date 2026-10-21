"""Exercise a downloaded authorization helper without real credentials."""

from __future__ import annotations

import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from tests.admin_client import TestClient

from src import main


def _available_listener_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return int(reservation.getsockname()[1])


def _await_helper(
    process: subprocess.Popen[str], opener: urllib.request.OpenerDirector, url: str
) -> dict:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=2)
            pytest.fail(
                f"Downloaded helper exited before startup: {process.returncode}\n"
                f"{stdout}\n{stderr}"
            )
        try:
            with opener.open(url + "/healthz", timeout=0.2) as response:
                return json.loads(response.read())
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            time.sleep(0.05)
    pytest.fail("Downloaded helper did not start its loopback listener within 10s")


@pytest.mark.parametrize("relay_prefix", ["", "/relay"])
def test_downloaded_helper_forwards_callback_to_baked_deployment_address(
    tmp_path, monkeypatch, relay_prefix: str
):
    captured: queue.Queue[dict] = queue.Queue()

    class MockRelayHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            captured.put(
                {
                    "path": self.path,
                    "host": self.headers["Host"],
                    "content_type": self.headers["Content-Type"],
                    "import_token": self.headers["X-Relay-Import-Token"],
                    "payload": json.loads(body),
                }
            )
            reply = b'{"success":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

    mock_relay = ThreadingHTTPServer(("127.0.0.1", 0), MockRelayHandler)
    relay_thread = threading.Thread(target=mock_relay.serve_forever, daemon=True)
    relay_thread.start()
    process = None
    try:
        relay_host = f"127.0.0.1:{mock_relay.server_address[1]}"
        relay_origin = f"http://{relay_host}"
        relay_base = relay_origin + relay_prefix
        listener_port = _available_listener_port()
        listener_origin = f"http://127.0.0.1:{listener_port}"

        for name in ("TRAE_RELAY_URL", "WEB_LOGIN_RELAY_URL", "TRAE_PUBLIC_BASE_URL"):
            monkeypatch.delenv(name, raising=False)
        if relay_prefix:
            monkeypatch.setenv("TRAE_PUBLIC_BASE_URL", relay_base)
        monkeypatch.setenv("WEB_LOGIN_LISTENER_PORT", str(listener_port))
        monkeypatch.setenv("TRAE_TRUST_PROXY_HEADERS", "0")

        client = TestClient(main.app, base_url=relay_origin)
        try:
            download = client.get("/web/login/download", params={"as": "py"})
        finally:
            client.close()
        assert download.status_code == 200
        assert download.headers["x-relay-base-url"] == relay_base
        assert download.headers["cache-control"] == "no-store"
        assert f'DEFAULT_RELAY_URL = "{relay_base}"' in download.text
        assert f"DEFAULT_LISTENER_PORT = {listener_port}" in download.text
        compile(download.text, "web_login.py", "exec")

        helper = tmp_path / "web_login.py"
        helper.write_bytes(download.content)
        child_env = os.environ.copy()
        child_env.pop("TRAE_RELAY_URL", None)
        for name in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ):
            child_env.pop(name, None)
        child_env["NO_PROXY"] = "127.0.0.1,localhost"
        child_env["PYTHONIOENCODING"] = "utf-8"
        process = subprocess.Popen(
            [sys.executable, "-u", str(helper), "--no-open"],
            cwd=tmp_path,
            env=child_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        health = _await_helper(process, opener, listener_origin)
        assert health == {"status": "ok", "relay": relay_base, "port": listener_port}

        retarget = urllib.parse.urlencode({"relay": "http://127.0.0.1:1"})
        with pytest.raises(urllib.error.HTTPError) as blocked:
            opener.open(listener_origin + "/set-relay?" + retarget, timeout=2)
        assert blocked.value.code == 404
        blocked.value.close()
        with opener.open(listener_origin + "/healthz", timeout=2) as response:
            assert json.loads(response.read())["relay"] == relay_base

        callback = urllib.parse.urlencode(
            {
                "userJwt": json.dumps(
                    {
                        "Token": "synthetic-test-access-token",
                        "RefreshToken": "synthetic-test-refresh-token",
                        "ClientID": "synthetic-test-client-id",
                    }
                ),
                "userInfo": json.dumps(
                    {
                        "UserID": "synthetic-test-user",
                        "TenantID": "synthetic-test-tenant",
                        "Region": "CN",
                        "ScreenName": "Test User",
                    }
                ),
                "login_trace_id": "synthetic-test-trace",
            }
        )
        with opener.open(listener_origin + "/authorize?" + callback, timeout=5) as response:
            assert response.status == 200
            assert "success:true" in response.read().decode("utf-8")

        request = captured.get(timeout=2)
        assert request["path"] == relay_prefix + "/api/web-auth"
        assert request["host"] == relay_host
        assert request["content_type"] == "application/json"
        assert request["import_token"] == "synthetic-test-trace"
        assert request["payload"]["token"] == "synthetic-test-access-token"
        assert request["payload"]["refreshToken"] == "synthetic-test-refresh-token"
        assert request["payload"]["userId"] == "synthetic-test-user"
        assert request["payload"]["tenantId"] == "synthetic-test-tenant"
        assert request["payload"]["screenName"] == "Test User"
        assert captured.empty()
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
        mock_relay.shutdown()
        mock_relay.server_close()
        relay_thread.join(timeout=5)
