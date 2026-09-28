"""检测流程使用的 HTTP 会话工具。"""
from __future__ import annotations

import uuid
from typing import Optional

from curl_cffi import requests as curl_requests


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
)


def make_session(
    proxy: str,
    *,
    impersonate: str = "",
    user_agent: str = "",
    accept_language: str = "",
):
    """创建带浏览器 TLS 指纹的 HTTP 会话。"""
    profile = impersonate or "chrome136"
    try:
        session = curl_requests.Session(impersonate=profile)
    except Exception:
        session = curl_requests.Session(impersonate="chrome136")
    session.headers.update(
        {
            "User-Agent": user_agent or DEFAULT_USER_AGENT,
            "Accept-Language": accept_language or "en-US,en;q=0.9",
        }
    )
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


def request(session, method: str, url: str, **kwargs):
    """发起请求；仅在 TLS 证书错误时进行一次兼容重试。"""
    verify = kwargs.pop("verify", True)
    attempts = [verify, False] if verify and url.startswith("https://") else [verify]
    last_error: Exception | None = None
    for current_verify in attempts:
        try:
            return session.request(method, url, verify=current_verify, **kwargs)
        except Exception as exc:
            last_error = exc
            detail = f"{type(exc).__name__}:{exc}".lower()
            if current_verify and any(
                marker in detail for marker in ("certificate", "ssl", "curl: (60)")
            ):
                continue
            raise
    if last_error is not None:
        raise last_error
    raise RuntimeError("request_failed")


def chatgpt_session(
    proxy: str,
    access_token: str,
    session_token: str = "",
    device_id: str = "",
    fingerprint: Optional[dict] = None,
):
    """创建仅用于读取结账信息的 ChatGPT 会话。"""
    fp = fingerprint if isinstance(fingerprint, dict) else {}
    session = make_session(
        proxy,
        impersonate=str(fp.get("impersonate") or ""),
        user_agent=str(fp.get("ua") or ""),
        accept_language=str(fp.get("accept_language") or ""),
    )
    stable_device_id = (
        str(device_id or "").strip()
        or str(fp.get("device_id") or "").strip()
        or str(uuid.uuid4())
    )
    cookies = [f"oai-did={stable_device_id}"]
    if session_token:
        cookies.extend(
            [
                f"__Secure-next-auth.session-token={session_token}",
                f"next-auth.session-token={session_token}",
            ]
        )
    session.headers.update(
        {
            "Authorization": f"Bearer {access_token}",
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Origin": "https://chatgpt.com",
            "Referer": "https://chatgpt.com/",
            "oai-device-id": stable_device_id,
            "oai-language": str(fp.get("oai_language") or "en-US"),
            "Cookie": "; ".join(cookies),
        }
    )
    return session
