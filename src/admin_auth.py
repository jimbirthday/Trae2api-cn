"""Administrator authentication, independent of model API keys.

Sessions and one-use account-import grants live in this process. Run one worker;
restarting the service revokes every session and outstanding grant.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import anyio
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

COOKIE = "relay_admin_session"
CSRF_HEADER = "x-admin-csrf"
IMPORT_HEADER = "x-relay-import-token"
LOGIN_PATH = "/admin/login"
SESSION_SECONDS = 12 * 60 * 60
GRANT_SECONDS = 10 * 60

# Everything else below /api is management, including future endpoints.
MODEL_INGRESS = frozenset(
    {
        "/api/ide/v2/llm_raw_chat",
        "/api/agent/v3/llm_raw_chat_custom_model",
        "/api/agent/v3/custom_model_proxy/chat",
        "/api/agent/v3/custom_model_connectivity_check",
        "/api/ide/v1/custom_model_connectivity_check",
    }
)


def management_path(path: str) -> bool:
    path = path.rstrip("/") or "/"
    return (
        ((path == "/api" or path.startswith("/api/")) and path not in MODEL_INGRESS)
        or path in {"/v1/status", "/authorize", "/docs", "/redoc", "/openapi.json"}
        or (path == "/web" or path.startswith("/web/"))
        or path == "/admin"
        or path.startswith("/admin/")
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass
class Session:
    expires: float
    csrf: str
    grants: dict[str, float] = field(default_factory=dict)


class AdminAuth:
    def __init__(self, password: str, *, secure_cookie: bool = False):
        # Keep a salted, expensive verifier in memory, never a plaintext copy.
        self.configured = (
            12 <= len(password) <= 1024
            and bool(password.strip())
            and password != "your-admin-password"
        )
        self.salt = secrets.token_bytes(16)
        self.verifier = self._derive(password) if self.configured else b""
        self.secure_cookie = secure_cookie
        self.sessions: OrderedDict[str, Session] = OrderedDict()
        self.attempts: dict[str, deque[float]] = {}
        self.global_attempts: deque[float] = deque()
        self.lock = threading.RLock()
        self.password_slots = threading.BoundedSemaphore(4)

    @classmethod
    def from_env(cls) -> AdminAuth:
        password = os.environ.get("RELAY_ADMIN_PASSWORD", "")
        password_file = os.environ.get("RELAY_ADMIN_PASSWORD_FILE", "")
        if password_file:
            try:
                password = Path(password_file).read_text(encoding="utf-8").rstrip("\r\n")
            except OSError:
                logging.getLogger(__name__).error("Cannot read RELAY_ADMIN_PASSWORD_FILE")
                password = ""
        instance = cls(
            password,
            secure_cookie=os.environ.get("RELAY_ADMIN_COOKIE_SECURE", "").lower()
            in {"1", "true", "yes"},
        )
        if not instance.configured:
            logging.getLogger(__name__).warning(
                "Admin access locked: set RELAY_ADMIN_PASSWORD to at least 12 characters"
            )
        return instance

    def _derive(self, password: str) -> bytes:
        return hashlib.scrypt(password.encode(), salt=self.salt, n=16384, r=8, p=1)

    def verify(self, password: str) -> bool:
        # Limit concurrent KDF memory usage during distributed login attempts.
        with self.password_slots:
            return self.configured and secrets.compare_digest(self.verifier, self._derive(password))

    def allow_attempt(self, host: str) -> bool:
        now = time.monotonic()
        with self.lock:
            # Bound memory and CPU even when many different client IPs connect.
            for key in list(self.attempts):
                if not self.attempts[key] or self.attempts[key][-1] <= now - 300:
                    del self.attempts[key]
            while self.global_attempts and self.global_attempts[0] <= now - 60:
                self.global_attempts.popleft()
            if len(self.global_attempts) >= 100:
                return False
            if host not in self.attempts and len(self.attempts) >= 4096:
                return False
            attempts = self.attempts.setdefault(host, deque())
            while attempts and attempts[0] <= now - 300:
                attempts.popleft()
            if len(attempts) >= 5:
                return False
            attempts.append(now)
            self.global_attempts.append(now)
            return True

    def create_session(self) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        session = Session(time.monotonic() + SESSION_SECONDS, secrets.token_urlsafe(32))
        with self.lock:
            now = time.monotonic()
            for key in list(self.sessions):
                if self.sessions[key].expires <= now:
                    del self.sessions[key]
            while len(self.sessions) >= 256:
                self.sessions.popitem(last=False)
            self.sessions[_digest(token)] = session
        return token, session

    def session(self, request: Request) -> Session | None:
        token = request.cookies.get(COOKIE, "")
        if not token or len(token) > 128:
            return None
        with self.lock:
            key = _digest(token)
            session = self.sessions.get(key)
            if session and session.expires <= time.monotonic():
                del self.sessions[key]
                return None
            return session

    def revoke(self, request: Request) -> None:
        with self.lock:
            self.sessions.pop(_digest(request.cookies.get(COOKIE, "")), None)

    def grant(self, session: Session) -> str:
        token = secrets.token_urlsafe(32)
        with self.lock:
            now = time.monotonic()
            session.grants = {key: expiry for key, expiry in session.grants.items() if expiry > now}
            if len(session.grants) >= 16:
                session.grants.pop(next(iter(session.grants)))
            session.grants[_digest(token)] = now + GRANT_SECONDS
        return token

    def consume_grant(self, token: str, owner: Session | None = None) -> bool:
        if not token or len(token) > 128:
            return False
        now = time.monotonic()
        key = _digest(token)
        with self.lock:
            for session in self.sessions.values():
                if owner is not None and session is not owner:
                    continue
                if session.expires > now and session.grants.pop(key, 0) > now:
                    return True
        return False


def same_origin(request: Request) -> bool:
    # Never trust arbitrary X-Forwarded-* here. Uvicorn can normalize the scheme
    # when the connection is from an explicitly trusted reverse proxy.
    if request.headers.get("sec-fetch-site") == "cross-site":
        return False
    origin = request.headers.get("origin")
    if not origin:
        return True  # Non-browser clients still need a session and CSRF token.
    try:
        parsed = urlsplit(origin)
        return (
            parsed.scheme in {"http", "https"}
            and parsed.scheme == request.url.scheme
            and parsed.netloc.lower() == request.url.netloc.lower()
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


def _error(status: int, message: str, **headers) -> JSONResponse:
    return JSONResponse({"success": False, "error": message}, status_code=status, headers=headers)


def install(app: FastAPI, admin: AdminAuth) -> None:
    # Stored on app.state so tests can supply an isolated real authentication
    # service without adding any production bypass switches.
    app.state.admin_auth = admin

    @app.middleware("http")
    async def admin_guard(request: Request, call_next):
        path = request.url.path.rstrip("/") or "/"
        # Helpers contain public deployment parameters only. Launchers fetch
        # them without browser cookies; they cannot import accounts unauthenticated.
        if not management_path(path) or path == "/web/login/download":
            return await call_next(request)
        service = request.app.state.admin_auth
        if path not in {LOGIN_PATH, "/api/admin/login"}:
            if not service.configured:
                if path == "/web/login" and request.method in {"GET", "HEAD"}:
                    response = RedirectResponse(LOGIN_PATH, status_code=303)
                else:
                    response = _error(
                        503, "管理员尚未配置：请设置至少 12 位的 RELAY_ADMIN_PASSWORD 并重启服务"
                    )
            else:
                session = service.session(request)
                request.state.admin_session = session
                imported = (
                    path == "/api/web-auth"
                    and request.method == "POST"
                    and (service.consume_grant(request.headers.get(IMPORT_HEADER, "")))
                )
                if imported:
                    response = await call_next(request)
                elif not session:
                    if path == "/web/login" and request.method in {"GET", "HEAD"}:
                        response = RedirectResponse(LOGIN_PATH, status_code=303)
                    else:
                        response = _error(401, "请先登录管理员账号")
                elif path == "/authorize":
                    trace = request.query_params.get("loginTraceID") or request.query_params.get(
                        "login_trace_id", ""
                    )
                    if request.method != "GET" or not service.consume_grant(trace, session):
                        response = _error(403, "授权请求已过期或已使用，请从控制台重新发起授权")
                    else:
                        response = await call_next(request)
                elif request.method not in {"GET", "HEAD", "OPTIONS"} and (
                    not same_origin(request)
                    or not secrets.compare_digest(
                        request.headers.get(CSRF_HEADER, "").encode(), session.csrf.encode()
                    )
                ):
                    response = _error(403, "请求校验失败，请刷新控制台后重试")
                else:
                    response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        return response

    @app.get(LOGIN_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def login_page(request: Request):
        if request.app.state.admin_auth.session(request):
            return RedirectResponse("/web/login", status_code=303)
        return HTMLResponse(_login_html(request.app.state.admin_auth.configured))

    @app.post("/api/admin/login", include_in_schema=False)
    async def login(request: Request):
        service = request.app.state.admin_auth
        if not service.configured:
            return _error(503, "请设置至少 12 位的 RELAY_ADMIN_PASSWORD 并重启服务")
        if (
            not same_origin(request)
            or request.headers.get("content-type", "").split(";")[0].strip() != "application/json"
        ):
            return _error(403, "请求来源或格式无效")
        host = request.client.host if request.client else "unknown"
        if not service.allow_attempt(host):
            return _error(429, "登录尝试过多，请 5 分钟后重试", **{"Retry-After": "300"})
        # Bound the request before parsing JSON or running the password KDF.
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 4096:
                return _error(413, "登录请求过大")
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return _error(400, "请求格式无效")
        password = body.get("password") if isinstance(body, dict) else None
        if not isinstance(password, str) or len(password) > 1024:
            return _error(400, "请输入管理员密码")
        if not await anyio.to_thread.run_sync(service.verify, password):
            return _error(401, "管理员密码错误")
        # A successful new login replaces this browser's previous session.
        service.revoke(request)
        token, session = service.create_session()
        response = JSONResponse(
            {"success": True, "csrf_token": session.csrf, "expires_in": SESSION_SECONDS}
        )
        response.set_cookie(
            COOKIE,
            token,
            max_age=SESSION_SECONDS,
            httponly=True,
            secure=service.secure_cookie or request.url.scheme == "https",
            samesite="lax",
            path="/",
        )
        return response

    @app.get("/api/admin/session", include_in_schema=False)
    async def current_session(request: Request):
        session = request.state.admin_session
        return JSONResponse({"success": True, "csrf_token": session.csrf})

    @app.post("/api/admin/logout", include_in_schema=False)
    async def logout(request: Request):
        request.app.state.admin_auth.revoke(request)
        response = JSONResponse({"success": True})
        response.delete_cookie(COOKIE, path="/")
        return response

    @app.post("/api/admin/oauth-state", include_in_schema=False)
    async def oauth_state(request: Request):
        service = request.app.state.admin_auth
        return JSONResponse({"success": True, "state": service.grant(request.state.admin_session)})


def _login_html(configured: bool) -> str:
    # Support password managers, paste and submitting with the Enter key.
    hint = (
        "输入管理员密码以管理账号、授权和服务设置。"
        if configured
        else ("管理员访问尚未启用。请设置至少 12 位的 RELAY_ADMIN_PASSWORD，并重启服务。")
    )
    disabled = "" if configured else " disabled"
    return """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>管理员登录 · Trae CN Relay</title>
<style>
:root{--bg:#f2f4f2;--card:#fff;--text:#17211c;--muted:#53635a;--edge:#abb8af;--accent:#176b45;--error:#b42318}
@media(prefers-color-scheme:dark){:root{--bg:#090c0b;--card:#121a16;--text:#edf5ef;--muted:#afbeb3;--edge:#607568;--accent:#146c43;--error:#ffa69e}}
*{box-sizing:border-box}body{margin:0;min-height:100svh;display:grid;place-items:center;padding:24px;background:var(--bg);color:var(--text);font:16px/1.6 system-ui,-apple-system,"PingFang SC",sans-serif}
main{width:100%;max-width:420px;padding:32px;background:var(--card);border:1px solid var(--edge);border-radius:16px}
.brand{color:var(--muted);font-size:14px;font-weight:600;letter-spacing:.03em}h1{font-size:26px;margin:8px 0}p{color:var(--muted);margin:0 0 24px}
label{display:block;font-weight:600;margin-bottom:8px}input,button{font:inherit;width:100%;min-height:48px;border-radius:8px}input{padding:10px 12px;border:1px solid var(--edge);background:var(--card);color:var(--text)}
button{margin-top:16px;border:0;background:var(--accent);color:#fff;font-weight:600;cursor:pointer}button:hover{filter:brightness(1.1)}button:active{filter:brightness(.9)}button:disabled{opacity:.6;cursor:wait}
:focus-visible{outline:3px solid var(--accent);outline-offset:3px}#error{color:var(--error);margin:12px 0 0;min-height:26px}.note{font-size:13px;margin:20px 0 0}
@media(max-width:420px){main{padding:24px}body{padding:16px}}
</style></head><body><main><div class="brand">Trae CN Relay</div><h1>管理员登录</h1>
<p>__ADMIN_HINT__</p><form id="login-form">
<input type="text" name="username" autocomplete="username" value="admin" hidden>
<label for="password">管理员密码</label><input id="password" name="password" type="password" autocomplete="current-password" required aria-describedby="error"__ADMIN_DISABLED__>
<button id="submit" type="submit"__ADMIN_DISABLED__>登录控制台</button>
<p id="error" role="alert" aria-live="assertive"></p></form>
<p class="note">管理员密码由部署者配置。</p></main>
<script>
document.getElementById('login-form').addEventListener('submit',async function(event){
event.preventDefault();var button=document.getElementById('submit'),error=document.getElementById('error'),input=document.getElementById('password');
button.disabled=true;button.textContent='正在登录…';error.textContent='';input.removeAttribute('aria-invalid');
try{var response=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:input.value})});
var data=await response.json();if(response.ok){input.value='';location.replace('/web/login');return;}
error.textContent=data.error||'登录失败';input.setAttribute('aria-invalid','true');input.focus();
}catch(e){error.textContent='无法连接服务器，请稍后重试';}
finally{button.disabled=false;button.textContent='登录控制台';}
});
</script></body></html>""".replace("__ADMIN_HINT__", hint).replace("__ADMIN_DISABLED__", disabled)
