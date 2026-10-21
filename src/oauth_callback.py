"""Parse a pasted loopback OAuth callback without visiting the URL."""

from urllib.parse import parse_qsl, urlsplit

MAX_CALLBACK_LENGTH = 65536


def parse_callback_url(value: object, listener_port: int) -> dict[str, str]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("请粘贴授权完成后的完整回调地址")
    value = value.strip()
    if len(value) > MAX_CALLBACK_LENGTH or any(ord(char) < 32 for char in value):
        raise ValueError("回调地址格式无效")
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme == "http"
            and parsed.hostname == "127.0.0.1"
            and parsed.port == listener_port
            and parsed.username is None
            and parsed.password is None
            and parsed.path == "/authorize"
            and bool(parsed.query)
            and not parsed.fragment
        )
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=64)
    except ValueError:
        raise ValueError("回调地址格式无效") from None
    if not valid:
        raise ValueError(f"请粘贴 http://127.0.0.1:{listener_port}/authorize 开头的完整回调地址")
    params = dict(pairs)
    if len(params) != len(pairs):
        raise ValueError("回调地址包含重复参数，请重新发起授权")
    traces = [params[key] for key in ("loginTraceID", "login_trace_id") if params.get(key)]
    if not traces or len(set(traces)) != 1:
        raise ValueError("回调地址缺少有效的授权标识，请从控制台重新发起授权")
    return params
