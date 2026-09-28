# -*- coding: utf-8 -*-
"""Web 部署证明（oai-web-deployment-attestation）获取。

attestation 是前端部署级签名（payload + 32B 签名，~1 小时有效，绑定部署版本
deployId）。它不是前端 JS 现算的，而是从 chatgpt.com 页面 HTML/RSC payload 中
expose 的 `webDeploymentAttestation` 字段抓取，因此纯协议可以拿到。

优先级：
  1. 环境变量 MIN_GCASH_ATTESTATION（人工从浏览器/DevTools 复制，1h 复用）
  2. 环境变量 MIN_OAICS_ATTESTATION（兼容 engines/freepp-backend 约定）
  3. 同会话 GET chatgpt.com 页面 HTML，正则抓 webDeploymentAttestation
  4. 都没有 → 返回空串（调用方按”无 attestation“降级；建单阶段可由哨兵单独通过）
"""
from __future__ import annotations

import os
import re
from typing import Optional

_ATTESTATION_RE = re.compile(r'"webDeploymentAttestation"\s*:\s*"([^"]+)"')
_ATTESTATION_ALT_RE = re.compile(r'[^A-Za-z0-9]webDeploymentAttestation[=:]\s*["\']?([A-Za-z0-9._-]+)')


def env_attestation() -> str:
    """优先环境变量注入（人工抓取值，~1 小时有效）。"""
    for key in ("MIN_GCASH_ATTESTATION", "MIN_OAICS_ATTESTATION"):
        value = str(os.environ.get(key) or "").strip()
        if value and "." in value:
            return value
    return ""


def extract_attestation_from_html(html: str) -> str:
    """从页面 HTML/RSC payload 抓取 webDeploymentAttestation。"""
    text = str(html or "")
    for pattern in (_ATTESTATION_RE, _ATTESTATION_ALT_RE):
        match = pattern.search(text)
        if match:
            value = match.group(1).strip()
            if value and "." in value:
                return value
    return ""


def fetch_attestation(
    http_get,
    *,
    url: str = "https://chatgpt.com/",
    headers: Optional[dict] = None,
    timeout: float = 30.0,
    emit=None,
) -> str:
    """获取 attestation：env 优先，其次页面 HTML（同会话/代理）。

    http_get = 返回带 .status_code/.text 的响应对象（curl_cffi 会话 get）。
    任何失败返回空串（不阻断）。
    """
    log = emit or (lambda stage, status, msg: None)
    value = env_attestation()
    if value:
        log("attestation", "run", "使用环境变量注入的部署证明（~1h 有效）")
        return value
    # ★ 默认**不再抓页面**：这一下是 445 KiB 的整页 HTML，而实测它**从来没**
    #   抓到过东西 —— 每次查优惠的日志都是同一行：
    #       attestation warn 页面未暴露 webDeploymentAttestation，未携带 attestation
    #   也就是说抓完跟不抓，发出去的请求**一模一样**（都是没有 attestation 头），
    #   白白多下 445 KiB —— 查优惠总共才 471 KiB，这一下就占 94%。
    #
    #   要用页面抓取：TURB_ATTESTATION_FETCH=1
    #   想省掉整页、只想人工灌一个：把值写进 MIN_GCASH_ATTESTATION（~1h 有效），
    #   上面 env_attestation() 会先命中，这里根本走不到。
    if str(os.environ.get("TURB_ATTESTATION_FETCH", "0")).strip().lower() not in ("1", "true", "yes"):
        log("attestation", "skip", "跳过部署证明页面抓取（省 ~445 KiB；设 TURB_ATTESTATION_FETCH=1 可开）")
        return ""
    try:
        response = http_get(url, headers=headers or {}, timeout=timeout)
    except Exception as e:
        log("attestation", "warn", "部署证明页面读取失败：" + type(e).__name__ + "，未携带 attestation")
        return ""
    if int(getattr(response, "status_code", 0) or 0) != 200:
        log("attestation", "warn", "部署证明页面 HTTP " + str(getattr(response, "status_code", "?")) + "，未携带 attestation")
        return ""
    value = extract_attestation_from_html(getattr(response, "text", "") or "")
    if value:
        log("attestation", "ok", "已从页面抓取部署证明（len=" + str(len(value)) + "）")
    else:
        log("attestation", "warn", "页面未暴露 webDeploymentAttestation，未携带 attestation")
    return value
