# -*- coding: utf-8 -*-
"""Skyvern 云端浏览器 Codex OAuth 入口。"""
from __future__ import annotations

from core.browser_use_codex_oauth import run_browser_use_codex_oauth


def run_skyvern_codex_oauth(email: str, otp_provider=None, proxy: str | None = None, force: bool = False) -> dict:
    return run_browser_use_codex_oauth(
        email=email,
        otp_provider=otp_provider,
        proxy=proxy,
        force=force,
        cloud_provider="skyvern",
    )
