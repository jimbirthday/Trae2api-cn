"""Authenticated client for existing management functionality tests.

Seed a real session rather than disabling either authentication middleware.
Security tests use fastapi.testclient.TestClient directly and exercise login.
"""

from fastapi.testclient import TestClient as AnonymousClient

from src.admin_auth import COOKIE, CSRF_HEADER


class TestClient(AnonymousClient):
    __test__ = False

    def __init__(self, app, *args, **kwargs):
        super().__init__(app, *args, **kwargs)
        token, session = app.state.admin_auth.create_session()
        self.cookies.set(COOKIE, token)
        self.headers[CSRF_HEADER] = session.csrf
