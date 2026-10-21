"""授权助手脚本生成与下载接口测试。

覆盖：部署地址自动注入（IP/端口）、bat/sh 生成、模板哨兵常量、地址注入防护，
以及控制台下载按钮指向自动生成的链接。
"""

import os
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

import pytest
from tests.admin_client import TestClient

from src import auth_helper
from src.auth_helper import RelayURLError


REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def isolated_helper_environment(monkeypatch):
    for name in ("TRAE_PUBLIC_BASE_URL", "TRAE_RELAY_URL", "WEB_LOGIN_RELAY_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TRAE_TRUST_PROXY_HEADERS", "1")


class AddressResolutionTests(unittest.TestCase):
    def test_host_header_wins_over_default(self):
        candidates = auth_helper.candidate_hosts(
            scheme="http", host="192.168.5.246:8000"
        )
        self.assertEqual(auth_helper.pick_relay_url(candidates), "http://192.168.5.246:8000")

    def test_public_env_variable_overrides_everything(self):
        candidates = auth_helper.candidate_hosts(
            public_base="https://relay.example.com",
            forwarded_proto="https",
            forwarded_host="proxy.internal:8443",
            scheme="http",
            host="127.0.0.1:8000",
        )
        self.assertEqual(candidates[0], "https://relay.example.com")

    def test_forwarded_headers_precede_browser_host(self):
        candidates = auth_helper.candidate_hosts(
            forwarded_proto="https",
            forwarded_host="ai.internal",
            scheme="http",
            host="127.0.0.1:8000",
        )
        self.assertEqual(candidates[0], "https://ai.internal")

    def test_unusable_candidates_fall_back_to_loopback(self):
        self.assertEqual(
            auth_helper.pick_relay_url(["", "not a url", "ftp://x"]),
            auth_helper.DEFAULT_RELAY_URL,
        )

    def test_rejects_injection_bearing_addresses(self):
        for bad in (
            'http://127.0.0.1:8000";import os;print(1)',
            "http://127.0.0.1:8000$(reboot)",
            "http://user:pw@127.0.0.1:8000",
            "http://127.0.0.1:8000 a",
            "127.0.0.1:8000",
            "http://relay:0",
            "http://relay:65536",
            "http://relay:",
            "http://relay:not-a-port",
            "http://relay/path%22",
            "http://relay/../other",
            "http://relay/a\\b",
            "http://relay/\ncmd",
            "http://[not-ipv6]:8000",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(RelayURLError):
                    auth_helper.normalize_relay_url(bad)

    def test_ipv6_and_proxy_prefix(self):
        self.assertEqual(
            auth_helper.normalize_relay_url("https://[::1]:9443/relay/"),
            "https://[::1]:9443/relay",
        )


class RenderTests(unittest.TestCase):
    def template(self) -> str:
        return (REPO_ROOT / "web_login.py").read_text(encoding="utf-8")

    def test_template_exposes_the_deployment_constants_block(self):
        text = self.template()
        self.assertIn("# ---- 部署默认值", text)
        for name in (
            "DEFAULT_RELAY_URL",
            "DEFAULT_LISTENER_PORT",
            "DEFAULT_CLIENT_ID",
            "DEFAULT_AUTH_URL",
        ):
            self.assertRegex(text, rf"(?m)^{name} = ")

    def test_generated_script_bakes_in_address_and_port(self):
        generated = auth_helper.render(
            "py",
            template=self.template(),
            relay_url="http://10.11.12.13:9100",
            listener_port=8766,
            client_id="ono9krqynydwx5",
            auth_url="https://www.trae.cn/authorization",
            generated_at="2026-10-13 01:00:00",
        )
        self.assertIn('DEFAULT_RELAY_URL = "http://10.11.12.13:9100"', generated)
        self.assertIn("DEFAULT_LISTENER_PORT = 8766", generated)
        self.assertIn("[--relay http://10.11.12.13:9100] [--port 8766]", generated)
        self.assertIn("# 中转站:   http://10.11.12.13:9100", generated)
        # 生成的脚本必须仍然是一份合法 python，且不含任何哨兵/旧硬编码地址。
        compile(generated, "web_login.py", "exec")
        self.assertNotIn("__TRAE_RELAY_BASE_URL__", generated)
        self.assertNotIn("192.168.5.246", generated)

    def test_bat_and_sh_embed_the_deployment_address(self):
        bat = auth_helper.render(
            "bat",
            template="",
            relay_url="http://192.168.5.246:8000",
            listener_port=8765,
            client_id="x",
            auth_url="https://www.trae.cn/authorization",
            generated_at="",
        )
        self.assertIn('set "RELAY=http://192.168.5.246:8000"', bat)
        self.assertIn("\r\n", bat)
        sh = auth_helper.render(
            "sh",
            template="",
            relay_url="http://192.168.5.246:8000",
            listener_port=8765,
            client_id="x",
            auth_url="https://www.trae.cn/authorization",
            generated_at="",
        )
        self.assertIn('RELAY="http://192.168.5.246:8000"', sh)
        self.assertTrue(sh.startswith("#!/bin/sh"))

    def test_file_names_and_media_types(self):
        self.assertEqual(auth_helper.file_name("py"), "web_login.py")
        self.assertEqual(auth_helper.file_name("bat"), "start_auth.bat")
        self.assertEqual(auth_helper.file_name("sh", version="1.0.6"), "start_auth-1.0.6.sh")
        self.assertEqual(auth_helper.media_type("bat"), "application/octet-stream")
        self.assertTrue(auth_helper.media_type("py").startswith("text/plain"))

    def test_unsupported_kind_raises(self):
        with self.assertRaises(RelayURLError):
            auth_helper.render("exe", template="", relay_url="http://127.0.0.1:8000",
                               listener_port=8765, client_id="x", auth_url="y", generated_at="")

    def test_string_defaults_are_escaped_not_executed(self):
        import ast

        client_id = 'test"\\id\nvalue'
        auth_url = 'https://example.test/a"b'
        generated = auth_helper.render(
            "py", template=self.template(), relay_url="https://relay.example:9443",
            client_id=client_id, auth_url=auth_url,
        )
        values = {
            node.targets[0].id: ast.literal_eval(node.value)
            for node in ast.parse(generated).body
            if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id.startswith("DEFAULT_")
        }
        self.assertEqual(values["DEFAULT_CLIENT_ID"], client_id)
        self.assertEqual(values["DEFAULT_AUTH_URL"], auth_url)
        compile(generated, "web_login.py", "exec")

    def test_template_missing_constants_is_rejected(self):
        with self.assertRaises(RelayURLError):
            auth_helper.render("py", template="#!/usr/bin/env python3\n", relay_url="http://relay")

    def test_launchers_use_temporary_downloads_before_replacing_helper(self):
        for kind in ("bat", "sh"):
            with self.subTest(kind=kind):
                text = auth_helper.render(kind, relay_url="https://relay.example:9443")
                self.assertIn("TMP_HELPER", text)
                self.assertNotIn('-o "%HELPER%"', text)
                self.assertNotIn('-o "$HELPER"', text)
                self.assertIn("--relay", text)
                self.assertIn("--port", text)
                self.assertNotIn('if not exist "%HELPER%"', text)
                self.assertNotIn('if [ ! -f "$HELPER" ]', text)
                if kind == "bat":
                    self.assertIn('if exist "%HELPER%\\"', text)
                else:
                    self.assertIn('if [ -d "$HELPER" ]', text)


class DownloadEndpointTests(unittest.TestCase):
    def setUp(self):
        from src.main import app

        self.client = TestClient(app)

    def test_browser_origin_is_baked_into_download(self):
        response = self.client.get(
            "/web/login/download",
            params={"as": "py", "relay": "http://192.168.9.9:8123"},
            headers={"host": "192.168.9.9:8123"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('DEFAULT_RELAY_URL = "http://192.168.9.9:8123"', response.text)
        self.assertIn('attachment; filename="web_login.py"', response.headers["content-disposition"])
        self.assertEqual(response.headers["x-relay-base-url"], "http://192.168.9.9:8123")
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_host_header_used_when_browser_omits_relay(self):
        response = self.client.get(
            "/web/login/download", params={"as": "py"}, headers={"host": "192.168.5.246:8000"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('DEFAULT_RELAY_URL = "http://192.168.5.246:8000"', response.text)

    def test_bat_download(self):
        response = self.client.get(
            "/web/login/download",
            params={"as": "bat", "relay": "http://192.168.9.9:8123"},
            headers={"host": "192.168.9.9:8123"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('set "RELAY=http://192.168.9.9:8123"', response.text)
        self.assertIn('filename="start_auth.bat"', response.headers["content-disposition"])

    def test_sh_download(self):
        response = self.client.get(
            "/web/login/download",
            params={"as": "sh", "relay": "http://192.168.9.9:8123"},
            headers={"host": "192.168.9.9:8123"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('RELAY="http://192.168.9.9:8123"', response.text)

    def test_invalid_kind_rejected(self):
        response = self.client.get("/web/login/download", params={"as": "com"})
        self.assertEqual(response.status_code, 400)

    def test_hostile_relay_param_never_reaches_the_script(self):
        evil = 'http://127.0.0.1:8000";import os;print("pwned'
        response = self.client.get(
            "/web/login/download",
            params={"as": "py", "relay": evil},
            headers={"host": "192.168.5.246:8000"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("pwned", response.text)
        self.assertIn('DEFAULT_RELAY_URL = "http://192.168.5.246:8000"', response.text)
        compile(response.text, "web_login.py", "exec")

    def test_helper_info_reports_generated_address(self):
        response = self.client.get(
            "/web/login/helper-info",
            params={"relay": "http://192.168.9.9:8123"},
            headers={"host": "192.168.9.9:8123"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["relay_url"], "http://192.168.9.9:8123")
        self.assertTrue(payload["generated_py"].startswith("/web/login/download"))
        self.assertEqual(payload["generated_sh"], "/web/login/download?as=sh")
        self.assertFalse(any(key.startswith("release_") for key in payload))

    def test_download_cannot_be_retargeted_to_an_unrelated_host(self):
        for endpoint in ("/web/login/download", "/web/login/helper-info"):
            with self.subTest(endpoint=endpoint):
                response = self.client.get(
                    endpoint, params={"relay": "https://attacker.example"},
                    headers={"host": "192.168.5.246:8000"},
                )
                self.assertEqual(response.status_code, 400)

    def test_ipv6_address_download(self):
        response = self.client.get(
            "/web/login/download", headers={"host": "[::1]:9123"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["x-relay-base-url"], "http://[::1]:9123")
        compile(response.text, "web_login.py", "exec")

    def test_missing_python_template_blocks_all_download_formats(self):
        from src import main

        with patch.object(main, "WEB_LOGIN_SCRIPT", REPO_ROOT / "missing-helper.py"):
            for kind in ("py", "bat", "sh"):
                with self.subTest(kind=kind):
                    response = self.client.get("/web/login/download", params={"as": kind})
                    self.assertEqual(response.status_code, 404)

    def test_explicit_invalid_deployment_configuration_is_reported(self):
        with patch.dict(os.environ, {"TRAE_PUBLIC_BASE_URL": "http://relay:99999"}):
            for endpoint in ("/web/login/download", "/web/login/helper-info"):
                with self.subTest(endpoint=endpoint):
                    self.assertEqual(self.client.get(endpoint).status_code, 400)

    def test_helper_info_and_download_use_the_same_callback_port(self):
        with patch.dict(os.environ, {"WEB_LOGIN_LISTENER_PORT": "9345"}):
            info = self.client.get("/web/login/helper-info")
            download = self.client.get("/web/login/download")
        self.assertEqual(info.json()["listener_port"], 9345)
        self.assertIn("DEFAULT_LISTENER_PORT = 9345", download.text)


class ConsolePageTests(unittest.TestCase):
    def setUp(self):
        from src.main import app

        self.client = TestClient(app)

    def test_download_buttons_point_at_generated_helper(self):
        html = self.client.get("/web/login").text
        self.assertIn('href="/web/login/download?as=py"', html)
        self.assertIn('href="/web/login/download?as=bat"', html)
        self.assertIn('href="/web/login/download?as=sh"', html)
        self.assertNotIn("releases/latest/download/web_login.py", html)

    def test_console_checks_helper_target_without_mutating_it(self):
        html = self.client.get("/web/login").text
        self.assertNotIn("/set-relay", html)
        self.assertIn("refreshHelperDownloadLinks", html)
        self.assertIn("normalizeHelperBase(expected.relay_url)", html)
        self.assertIn("window.location.origin", html)

    def test_helper_template_is_shipped_in_repository(self):
        self.assertTrue((REPO_ROOT / "web_login.py").exists())
        self.assertTrue((REPO_ROOT / "start_auth.bat").exists())


class HelperScriptSelfTests(unittest.TestCase):
    def test_local_helper_normalizes_and_rejects_junk(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("web_login_template", REPO_ROOT / "web_login.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.normalize_relay_url("192.168.5.246:8000"), "http://192.168.5.246:8000")
        self.assertEqual(module.normalize_relay_url("http://a.b:8000/"), "http://a.b:8000")
        self.assertEqual(module.normalize_relay_url("http://a.b:8000/x?a=1"), "")
        self.assertEqual(module.normalize_relay_url("javascript:alert(1)"), "")
        self.assertTrue(module.default_relay_url())

    def test_oauth_result_escapes_trace_as_json(self):
        import importlib.util
        import json

        spec = importlib.util.spec_from_file_location("web_login_template", REPO_ROOT / "web_login.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        handler = object.__new__(module.RelayAuthHandler)
        message = "error';alert(1);//</script>"
        trace = "trace';alert(2);//</script>"
        html = handler._oauth_result_page(False, message, trace)
        self.assertIn('msg.error = ' + json.dumps(message).replace("<", "\\u003c"), html)
        self.assertIn('loginTraceId:' + json.dumps(trace).replace("<", "\\u003c"), html)
        self.assertNotIn("//</script>", html)

    def test_helper_target_cannot_be_rewritten_by_an_arbitrary_webpage(self):
        text = (REPO_ROOT / "web_login.py").read_text(encoding="utf-8")
        self.assertNotIn("/set-relay", text)
        self.assertIn('parsed.path == "/healthz"', text)


class DeploymentEnvTests(unittest.TestCase):
    def _download(self, headers=None, params=None, env=None):
        from src.main import app

        original = dict(os.environ)
        os.environ.update(env or {})
        try:
            client = TestClient(app)
            return client.get(
                "/web/login/download", params=params or {"as": "py"}, headers=headers or {}
            )
        finally:
            os.environ.clear()
            os.environ.update(original)

    def test_explicit_deployment_env_wins_over_browser(self):
        response = self._download(
            headers={"host": "127.0.0.1:8000"},
            params={"as": "py", "relay": "http://192.168.9.9:8123"},
            env={"TRAE_PUBLIC_BASE_URL": "https://gateway.internal:8443"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('DEFAULT_RELAY_URL = "https://gateway.internal:8443"', response.text)

    def test_proxy_headers_can_be_disabled(self):
        response = self._download(
            headers={
                "host": "192.168.5.246:8000",
                "x-forwarded-host": "attacker.example",
                "x-forwarded-proto": "https",
            },
            env={"TRAE_TRUST_PROXY_HEADERS": "0"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('DEFAULT_RELAY_URL = "http://192.168.5.246:8000"', response.text)
        self.assertNotIn("attacker.example", response.text)

    def test_proxy_headers_are_used_when_trusted(self):
        response = self._download(
            headers={
                "host": "127.0.0.1:8000",
                "x-forwarded-host": "relay.example.com",
                "x-forwarded-proto": "https",
            },
            env={"TRAE_TRUST_PROXY_HEADERS": "1"},
        )
        self.assertIn('DEFAULT_RELAY_URL = "https://relay.example.com"', response.text)

    def test_forwarded_scheme_without_forwarded_host_preserves_external_port(self):
        response = self._download(
            headers={"host": "relay.example:9443", "x-forwarded-proto": "https"},
        )
        self.assertIn('DEFAULT_RELAY_URL = "https://relay.example:9443"', response.text)

    def test_listener_port_from_env_is_baked(self):
        response = self._download(
            headers={"host": "192.168.5.246:8000"},
            params={"as": "py", "relay": "http://192.168.5.246:8000"},
            env={"WEB_LOGIN_LISTENER_PORT": "9321"},
        )
        self.assertIn("DEFAULT_LISTENER_PORT = 9321", response.text)
        self.assertIn("[--relay http://192.168.5.246:8000] [--port 9321]", response.text)


class ReleaseAssetBuildTests(unittest.TestCase):
    def test_assets_are_generated_generically_and_loadable(self):
        import importlib.util
        import tempfile
        import zipfile

        spec = importlib.util.spec_from_file_location(
            "build_auth_helper_assets", REPO_ROOT / "scripts" / "build_auth_helper_assets.py"
        )
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as tmp:
            argv_backup = sys.argv
            sys.argv = ["build_auth_helper_assets.py", "--version", "9.9.9", "--output", tmp]
            try:
                self.assertEqual(module.main(), 0)
            finally:
                sys.argv = argv_backup
            output = Path(tmp)
            names = ["web_login.py", "start_auth.bat", "start_auth.sh",
                     "trae-auth-helper-9.9.9.zip", "trae-auth-helper-9.9.9.sha256"]
            for name in names:
                self.assertTrue((output / name).exists(), name)

            py = (output / "web_login.py").read_text(encoding="utf-8")
            # 通用版不能泄露任何人的内网地址，也不留未替换的占位符。
            compile(py, "web_login.py", "exec")
            self.assertIn(auth_helper.DEFAULT_RELAY_URL, py)
            self.assertNotIn("__TRAE_RELAY_BASE_URL__", py)
            self.assertNotIn("<relay-host>", py)
            self.assertNotIn("192.168.5.246", py)
            self.assertIn("通用版授权助手", py)

            bat_bytes = (output / "start_auth.bat").read_bytes()
            self.assertIn(b"\r\n", bat_bytes)
            bat = bat_bytes.decode("utf-8")
            self.assertNotIn("192.168.5.246", bat)
            sh = (output / "start_auth.sh").read_text(encoding="utf-8")
            self.assertTrue(sh.startswith("#!/bin/sh"))

            with zipfile.ZipFile(output / "trae-auth-helper-9.9.9.zip") as archive:
                self.assertIn("web_login.py", archive.namelist())
                self.assertIn("start_auth.bat", archive.namelist())
                self.assertIn("start_auth.sh", archive.namelist())


class RepositoryCopyTests(unittest.TestCase):
    def test_repository_helper_copies_are_generic(self):
        for name in ("start_auth.bat", "start_auth.sh"):
            text = (REPO_ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("192.168.5.246", text, name)
            self.assertNotIn("__TRAE_RELAY_BASE_URL__", text, name)
        shipped = (REPO_ROOT / "web_login.py").read_text(encoding="utf-8")
        self.assertNotIn("192.168.5.246", shipped)

    def test_console_offers_the_platform_matching_one_click_script(self):
        from src.main import app

        html = TestClient(app).get("/web/login").text
        self.assertIn('href="/web/login/download?as=sh"', html)
        self.assertIn('id="sh-link"', html)
        self.assertIn("pickHelperPlatformScript", html)


def test_console_helper_javascript_links_and_target_check():
    import json
    import re
    import shutil
    import subprocess
    from src import main

    node = shutil.which("node")
    if not node:
        pytest.skip("Node is not installed for console JavaScript verification")
    html = TestClient(main.app).get("/web/login").text
    source = re.search(r"(let localHelperError = .*?)async function startAuth", html, re.S).group(1)
    javascript = """
const vm = require('node:vm');
const assert = require('node:assert/strict');
(async function() {
  for (const [origin, prefix, platform] of [
    ['http://192.168.5.246:8123', '', 'Win32'],
    ['https://relay.example:9443', '/relay', 'Linux'],
    ['http://[::1]:9123', '', 'Win32']
  ]) {
    const elements = Object.fromEntries(['helper-py-link', 'bat-link', 'sh-link'].map(
      id => [id, {href: '', style: {}}]
    ));
    const requests = [];
    let helperRelay = origin + prefix;
    const context = {
      window: {location: {origin, pathname: prefix + '/web/login'}},
      navigator: {platform, userAgent: ''},
      document: {getElementById: id => elements[id]},
      URL, AbortController,
      setTimeout: () => 1, clearTimeout: () => {},
      fetch: async url => {
        requests.push(url);
        return {ok: true, json: async () => url.startsWith('http://127.0.0.1:')
          ? {relay: helperRelay} : {relay_url: origin + prefix}};
      }
    };
    vm.createContext(context);
    vm.runInContext(SOURCE, context);
    assert.equal(context.currentDeploymentBase(), origin + prefix);
    for (const [id, kind] of [
      ['helper-py-link', 'py'], ['bat-link', 'bat'], ['sh-link', 'sh']
    ]) {
      assert.equal(elements[id].href, prefix + '/web/login/download?as=' + kind
        + '&relay=' + encodeURIComponent(origin + prefix));
    }
    assert.equal(elements['bat-link'].style.display, platform === 'Win32' ? 'inline-flex' : 'none');
    assert.equal(await context.checkLocalListener(), true);
    helperRelay = 'http://other-deployment.example:8000';
    assert.equal(await context.checkLocalListener(), false);
    assert.ok(vm.runInContext('localHelperError', context));
    assert.ok(requests.every(url => !url.includes('/set-relay')));
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
""".replace("SOURCE", json.dumps(source))
    result = subprocess.run(
        [node], input=javascript, capture_output=True, text=True, encoding="utf-8", timeout=10
    )
    assert result.returncode == 0, result.stderr


if __name__ == "__main__":
    unittest.main()
