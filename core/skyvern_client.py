# -*- coding: utf-8 -*-
"""Skyvern Browser Sessions 客户端。"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from config import skyvern as _cfg

logger = logging.getLogger(__name__)


@dataclass
class SkyvernSession:
    connect_url: str
    api_key_present: bool
    proxy_country_code: str = ""
    profile_id: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    session_id: str = ""


class SkyvernClient:
    """最小 Skyvern Browser Session 客户端。"""

    def __init__(self, api_key: str | None = None, api_base: str | None = None):
        self.api_key = (api_key if api_key is not None else getattr(_cfg, "SKYVERN_API_KEY", "") or "").strip()
        self.api_base = (api_base if api_base is not None else getattr(_cfg, "SKYVERN_API_BASE", "") or "https://api.skyvern.com").rstrip("/")

    def require_api_key(self) -> str:
        if not self.api_key:
            raise RuntimeError("SKYVERN_API_KEY 为空。请在 .env 或 WebUI 配置页填写 Skyvern API Key。")
        return self.api_key

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self.require_api_key(),
            "content-type": "application/json",
            "accept": "application/json",
        }

    def cdp_headers(self) -> dict[str, str]:
        """连接 Skyvern browser_address WebSocket 时需要携带的认证头。"""
        api_key = self.require_api_key()
        return {
            "x-api-key": api_key,
            "Authorization": f"Bearer {api_key}",
        }

    @staticmethod
    def _session_id(data: dict[str, Any]) -> str:
        return str(data.get("browser_session_id") or data.get("session_id") or data.get("id") or "").strip()

    @staticmethod
    def _browser_address(data: dict[str, Any]) -> str:
        return str(data.get("browser_address") or data.get("cdp_url") or data.get("connect_url") or data.get("ws_endpoint") or "").strip()

    @staticmethod
    def _normalize_proxy_location(value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        upper = text.upper().replace("-", "_")
        aliases = {
            "JP": "RESIDENTIAL_JP",
            "JA": "RESIDENTIAL_JP",
            "JAPAN": "RESIDENTIAL_JP",
            "US": "RESIDENTIAL",
            "USA": "RESIDENTIAL",
            "GB": "RESIDENTIAL_GB",
            "UK": "RESIDENTIAL_GB",
            "IN": "RESIDENTIAL_IN",
            "DE": "RESIDENTIAL_DE",
            "FR": "RESIDENTIAL_FR",
            "AU": "RESIDENTIAL_AU",
            "CA": "RESIDENTIAL_CA",
            "KR": "RESIDENTIAL_KR",
            "NONE": "NONE",
        }
        if upper in aliases:
            return aliases[upper]
        if len(upper) == 2:
            return f"RESIDENTIAL_{upper}"
        return upper

    @staticmethod
    def _normalize_browser_type(value: str) -> str:
        text = str(value or "").strip().lower().replace("_", "-")
        aliases = {
            "": "stealth-chromium",
            "chromium": "stealth-chromium",
            "chromium-headful": "stealth-chromium",
            "headful": "stealth-chromium",
            "stealth": "stealth-chromium",
            "stealth-chrome": "stealth-chromium",
            "edge": "msedge",
            "microsoft-edge": "msedge",
        }
        return aliases.get(text, text)

    def create_browser_session(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "timeout": max(1, int(getattr(_cfg, "SKYVERN_BROWSER_SESSION_TIMEOUT", 60) or 60)),
        }
        profile_id = str(getattr(_cfg, "SKYVERN_BROWSER_PROFILE_ID", "") or "").strip()
        if profile_id:
            payload["browser_profile_id"] = profile_id
        proxy_location = self._normalize_proxy_location(str(getattr(_cfg, "SKYVERN_PROXY_LOCATION", "") or ""))
        if proxy_location:
            payload["proxy_location"] = proxy_location
        browser_type = self._normalize_browser_type(str(getattr(_cfg, "SKYVERN_BROWSER_TYPE", "") or ""))
        if browser_type:
            payload["browser_type"] = browser_type
        payload["generate_browser_profile"] = bool(getattr(_cfg, "SKYVERN_GENERATE_BROWSER_PROFILE", False))
        payload["ad_blocker"] = bool(getattr(_cfg, "SKYVERN_AD_BLOCKER", True))

        safe_payload = dict(payload)
        logger.info("[Skyvern] 创建 browser session: base=%s payload=%s", self.api_base, safe_payload)
        resp = requests.post(
            f"{self.api_base}/v1/browser_sessions",
            headers=self._headers(),
            json=payload,
            timeout=30,
        )
        try:
            data = resp.json()
        except Exception:
            data = {"text": resp.text[:1000]}
        if resp.status_code >= 400:
            raise RuntimeError(f"Skyvern create browser session HTTP {resp.status_code}: {data}")
        if not isinstance(data, dict):
            raise RuntimeError(f"Skyvern create browser session 响应不是对象: {data!r}")
        return data

    def get_browser_session(self, session_id: str) -> dict[str, Any]:
        resp = requests.get(
            f"{self.api_base}/v1/browser_sessions/{session_id}",
            headers=self._headers(),
            timeout=20,
        )
        try:
            data = resp.json()
        except Exception:
            data = {"text": resp.text[:1000]}
        if resp.status_code >= 400:
            raise RuntimeError(f"Skyvern get browser session HTTP {resp.status_code}: {data}")
        if not isinstance(data, dict):
            raise RuntimeError(f"Skyvern get browser session 响应不是对象: {data!r}")
        return data

    def close_browser_session(self, session_id: str) -> dict[str, Any]:
        resp = requests.post(
            f"{self.api_base}/v1/browser_sessions/{session_id}/close",
            headers=self._headers(),
            json={},
            timeout=20,
        )
        try:
            data = resp.json()
        except Exception:
            data = {"text": resp.text[:1000]}
        if resp.status_code >= 400:
            raise RuntimeError(f"Skyvern close browser session HTTP {resp.status_code}: {data}")
        return data if isinstance(data, dict) else {"ok": True, "data": data}

    def open_session(self) -> SkyvernSession:
        data = self.create_browser_session()
        session_id = self._session_id(data)
        address = self._browser_address(data)
        # create 响应有时先返回 session_id，browser_address 需要 get session 才出现。
        if session_id and not address:
            last = data
            for _ in range(10):
                time.sleep(1)
                last = self.get_browser_session(session_id)
                address = self._browser_address(last)
                if address:
                    data = {**data, "latest": last}
                    break
            if not address:
                raise RuntimeError(f"Skyvern browser session 缺少 browser_address/cdp_url: {last}")
        if not session_id:
            session_id = self._session_id(data.get("latest") or {}) if isinstance(data.get("latest"), dict) else ""
        if not address:
            raise RuntimeError(f"Skyvern browser session 缺少 browser_address/cdp_url: {data}")
        proxy_location = str(getattr(_cfg, "SKYVERN_PROXY_LOCATION", "") or "").strip()
        profile_id = str(getattr(_cfg, "SKYVERN_BROWSER_PROFILE_ID", "") or "").strip()
        safe_raw = dict(data)
        logger.info("[Skyvern] browser session 已创建：session_id=%s browser_address=%s", session_id or "-", address)
        return SkyvernSession(
            connect_url=address,
            api_key_present=True,
            proxy_country_code=proxy_location,
            profile_id=profile_id,
            raw=safe_raw,
            session_id=session_id,
        )
