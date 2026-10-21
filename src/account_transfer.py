"""Administrator-only, portable account credential backups."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
from datetime import UTC, datetime

import anyio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from . import auth

MAX_BYTES = 5 * 1024 * 1024
MAX_ACCOUNTS = 1000
FORMAT = "trae-cn-relay-accounts"
FIELDS = {
    "user_id": ("user_id", "userId", "web_id", "webId"),
    "label": ("label", "name", "screen_name", "screenName"),
    "token": ("token", "Token"),
    "refresh_token": ("refresh_token", "refreshToken", "RefreshToken"),
    "expired_at": ("expired_at", "expiredAt"),
    "refresh_expired_at": ("refresh_expired_at", "refreshExpiredAt"),
    "host": ("host",),
    "client_id": ("client_id", "clientId"),
    "source": ("source",),
    "edition": ("edition",),
}


def _jwt_metadata(token: str) -> dict:
    """Read optional identity hints only; upstream still authenticates the JWT.

    Imported JWTs are not signature-verified here. Never use their claims to
    authorize administrator access or replace the supplied refresh credential.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        encoded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.b64decode(encoded, altchars=b"-_", validate=True))
    except (ValueError, UnicodeDecodeError, binascii.Error, RecursionError):
        return {}
    if not isinstance(claims, dict):
        return {}
    data = claims.get("data")
    data = data if isinstance(data, dict) else {}
    result = {}
    for field, value in (("user_id", data.get("id")), ("tenantId", data.get("tenant_id"))):
        if type(value) is int:
            value = str(value)
        if isinstance(value, str) and 0 < len(value) <= 512 and all(ord(c) >= 32 for c in value):
            result[field] = value
    expires = claims.get("exp")
    if type(expires) in {int, float} and 0 < expires < 1e12 and math.isfinite(expires):
        result["expired_at"] = str(expires)
    return result


def normalize_accounts(document: object) -> list[tuple[str, dict]]:
    """Validate every row before changing any stored credentials."""
    rows = document
    if isinstance(document, dict):
        if document.get("format", FORMAT) != FORMAT or document.get("version", 1) != 1:
            raise ValueError("不支持的账号文件格式或版本")
        rows = document.get("accounts")
    if isinstance(rows, dict):
        rows = [(key, value) for key, value in rows.items()]
    elif isinstance(rows, list):
        rows = [(None, value) for value in rows]
    else:
        raise TypeError("请导入账号数组，或包含 accounts 数组/对象的 JSON 文件")
    if not rows or len(rows) > MAX_ACCOUNTS:
        raise ValueError(f"每次需导入 1–{MAX_ACCOUNTS} 个账号")
    result = []
    for index, (key, row) in enumerate(rows, 1):
        def invalid(message, row_index=index):
            # Never include identifiers or credential values in error responses.
            return ValueError(f"第 {row_index} 项：{message}")

        if not isinstance(row, dict):
            raise invalid("账号必须是 JSON 对象")
        record = {}
        for field, aliases in FIELDS.items():
            value = next((row[name] for name in aliases if row.get(name) not in (None, "")), "")
            if field in {"expired_at", "refresh_expired_at"} and type(value) in {int, float}:
                value = str(value)
            limit = 65536 if field in {"token", "refresh_token"} else 512
            if (
                not isinstance(value, str)
                or len(value) > limit
                or any(ord(char) < 32 for char in value)
            ):
                raise invalid(f"{field} 字段类型或长度无效")
            record[field] = value
        if not record["token"].strip():
            raise invalid("缺少 token，不能导入不含凭据的账号列表")
        metadata = _jwt_metadata(record["token"])
        # Native backup IDs take precedence; JWT headers are shared by many
        # accounts, so a token prefix is never a suitable fallback identifier.
        if not record["user_id"] and not row.get("id") and not key:
            record["user_id"] = metadata.get("user_id", "")
        if not record["expired_at"]:
            record["expired_at"] = metadata.get("expired_at", "")
        fingerprint = hashlib.sha256(record["token"].encode()).hexdigest()
        account_id = record["user_id"] or row.get("id") or key or "token-" + fingerprint
        if (
            not isinstance(account_id, str)
            or not account_id.strip()
            or len(account_id) > 512
            or any(ord(char) < 32 for char in account_id)
        ):
            raise invalid("账号标识无效")
        provider = row.get("provider_specific", {})
        if not isinstance(provider, dict):
            raise invalid("provider_specific 必须是 JSON 对象")
        provider = dict(provider)
        for field in ("deviceId", "machineId"):
            value = row.get(field, "")
            if not isinstance(value, str) or len(value) > 512:
                raise invalid(f"{field} 字段类型或长度无效")
            if value and not provider.get(field):
                provider[field] = value
        if metadata.get("tenantId") and not provider.get("tenantId"):
            provider["tenantId"] = metadata["tenantId"]
        if any(
            isinstance(value, str) and any(ord(char) < 32 for char in value)
            for value in provider.values()
        ):
            raise invalid("provider_specific 不能包含控制字符")
        if record["source"] not in {"", "web-login", "auto", "env", "manual", "cli"}:
            raise invalid("不支持的凭据来源 source")
        enabled = row.get("model_enabled", row.get("enabled", True))
        if not isinstance(enabled, bool):
            raise invalid("model_enabled 必须是布尔值")
        record.update(
            provider_specific=provider,
            model_enabled=enabled,
            source=record["source"] or "web-login",
            edition=record["edition"] or "cn",
            label=record["label"] or str(provider.get("screenName") or account_id),
        )
        result.append((account_id, record))
    return result


def export_document() -> dict:
    accounts = []
    for account_id, record in auth.get_accounts_raw():
        # Exclude cached credits/check-in data and server-wide settings.
        row = {field: record.get(field) or "" for field in FIELDS}
        row.update(
            id=account_id,
            provider_specific=record.get("provider_specific") or {},
            model_enabled=auth._record_model_enabled(record),
        )
        accounts.append(row)
    return {
        "format": FORMAT,
        "version": 1,
        "exported_at": datetime.now(UTC).isoformat(),
        "accounts": accounts,
    }


def install(app: FastAPI) -> None:
    # /api/accounts/* is guarded by administrator sessions and CSRF middleware.
    @app.post("/api/accounts/export")
    async def export_accounts():
        content = await anyio.to_thread.run_sync(export_document)
        filename = datetime.now(UTC).strftime("trae-accounts-%Y%m%d-%H%M%S.json")
        return Response(
            json.dumps(content, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )

    @app.post("/api/accounts/import")
    async def import_accounts(request: Request):
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > MAX_BYTES:
                return JSONResponse(
                    {"success": False, "error": "导入文件过大，最多 5 MiB"}, status_code=413
                )
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return JSONResponse(
                {"success": False, "error": "文件不是有效的 UTF-8 JSON"}, status_code=400
            )
        try:
            update = body.get("update_existing", False) if isinstance(body, dict) else False
            if not isinstance(update, bool):
                raise TypeError("update_existing 必须是布尔值")
            document = body.get("data", body) if isinstance(body, dict) else body
            records = normalize_accounts(document)
            counts = await anyio.to_thread.run_sync(auth.import_account_records, records, update)
        except (ValueError, TypeError) as error:
            return JSONResponse({"success": False, "error": str(error)}, status_code=400)
        except OSError:
            return JSONResponse(
                {"success": False, "error": "无法保存账号，请检查 data 目录写入权限和磁盘空间"},
                status_code=500,
            )
        return JSONResponse({"success": True, **counts})
