# -*- coding: utf-8 -*-
"""协议引擎 —— 把「已修好的协议注册机」的 Sentinel 路径接进 turb。

背景
----
turb 自带的 sentinel 路径（`sentinel/sentinel-runner.js` + `core/sentinel_runner.py`）
是 98KB 的成熟实现，但它走的是**合成 p + 自己造窗口**那条路，时区/locale 细节对不上
（实测：页面 locale 是 vi-VN，token 载荷里却是英文 `(Indochina Time)`）。

⚠️ 这里曾经写过「t 一直偏短（1024~1104，真浏览器 HAR ~1816）」—— **那是错的，已删除**。
   那个 1600 的阈值是 `core/sentinel_runner.py` 自己定的告警线，协议引擎根本不走它。
   协议机用同样的 t 长度（~988）已经成功注册了 33 个号（webui.db `registered` 表，
   最近一次 2026-09-22 17:30 前后，走 11911~11913 出口）。t 长短不是问题。

主人手上有一份**已经改好并验证过**的协议注册机（GPT-Register-Tool 的 `协议/`），
它直接跑 OpenAI 的**真 sdk.js**，两趟出 token。本模块就是那个路径的适配层 ——
不重写、不魔改，只做「turb 的画像 -> 协议机的 stdin JSON」这一层翻译。

两趟流程（与协议机完全一致）
--------------------------
  1) requirements : 用真 sdk.js 出 request_p
  2) 调用方拿 request_p 去打 /sentinel/req 拿 challenge   <-- 由 core/openai_auth.py 做
  3) solve        : 把 challenge 喂回去，出最终 token + so_token

对外只有两个函数：
  request_p(session, flow)                  -> str
  solve(session, flow, challenge, req_p)    -> (token, so_token)

引擎开关
--------
`SENTINEL_ENGINE` 环境变量：
  protocol（默认）—— 走本模块
  native          —— 走 turb 原来的 sentinel-runner.js
显式写进代码默认值，不动 `.env`；要回退只要 `$env:SENTINEL_ENGINE='native'`。
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SENTINEL_DIR = _PROJECT_ROOT / "sentinel"
_JS_PATH = _SENTINEL_DIR / "openai_sentinel_quickjs.js"
_SDK_PATH = _SENTINEL_DIR / "sdk.js"

_REQUIREMENTS_TIMEOUT = int(os.environ.get("SENTINEL_PROTO_REQ_TIMEOUT", "60"))
_SOLVE_TIMEOUT = int(os.environ.get("SENTINEL_PROTO_SOLVE_TIMEOUT", "120"))
_BEHAVIOR_MS = int(os.environ.get("SENTINEL_PROTO_BEHAVIOR_MS", "4200"))

DEFAULT_ENGINE = "protocol"


def engine() -> str:
    """当前 Sentinel 引擎：protocol（默认）或 native。"""
    return (os.environ.get("SENTINEL_ENGINE", "") or "").strip().lower() or DEFAULT_ENGINE


def use_protocol() -> bool:
    return engine() != "native"


def _node_bin() -> str:
    return (os.environ.get("OPENAI_SENTINEL_NODE_PATH", "") or "").strip() or (
        "node.exe" if sys.platform.startswith("win") else "node"
    )


def _ensure_files() -> None:
    if not _JS_PATH.exists():
        raise FileNotFoundError(
            f"找不到协议 JS: {_JS_PATH}\n"
            "它来自 GPT-Register-Tool 的 协议/openai_sentinel_quickjs.js（已修好的版本）。"
        )
    if not _SDK_PATH.exists():
        raise FileNotFoundError(f"找不到 sdk.js: {_SDK_PATH}")


def _run_action(action: str, payload: dict, timeout: int) -> dict:
    """把 payload 走 stdin 喂给协议 JS，读 stdout 的 JSON。

    协议 JS 的约定（见其文件头）：
      - 入参：stdin 上一整份 JSON，含 `action`
      - 出参：stdout 上一整份 JSON
      - 失败：非 0 退出码 + stderr 上的 stack
    环境变量 `OPENAI_SENTINEL_SDK_FILE` 指向 sdk.js（它自己不会下载）。
    """
    _ensure_files()
    body = dict(payload)
    body["action"] = action
    env = os.environ.copy()
    env["OPENAI_SENTINEL_SDK_FILE"] = str(_SDK_PATH)
    # 时区：协议 JS 自己按 IANA 名算，但 node 原生 Date 也读 TZ，一起设上更保险。
    tz = str(payload.get("timezone") or "").strip()
    if tz:
        env["TZ"] = tz

    started = time.time()
    try:
        proc = subprocess.run(
            [_node_bin(), str(_JS_PATH)],
            input=json.dumps(body, ensure_ascii=False),
            text=True,
            encoding="utf-8",
            capture_output=True,
            cwd=str(_PROJECT_ROOT),
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"协议 Sentinel 超时（>{timeout}s, action={action}）") from exc
    except FileNotFoundError as exc:
        raise RuntimeError(
            "未找到 Node 可执行文件，请确认已安装 Node.js 并在 PATH 里，"
            "或用 OPENAI_SENTINEL_NODE_PATH 指定绝对路径。"
        ) from exc

    elapsed = time.time() - started
    if proc.returncode != 0:
        raise RuntimeError(
            f"协议 Sentinel 退出码 {proc.returncode} (action={action})\n"
            f"stderr: {(proc.stderr or '').strip()[:600]}\n"
            f"stdout: {(proc.stdout or '').strip()[:300]}"
        )
    out = (proc.stdout or "").strip()
    if not out:
        raise RuntimeError(
            f"协议 Sentinel 输出为空 (action={action}), "
            f"stderr: {(proc.stderr or '').strip()[:400]}"
        )
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"协议 Sentinel 输出不是 JSON: {out[:300]}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("协议 Sentinel 输出不是 JSON 对象")
    logger.debug("[SentinelProto] action=%s 用时 %.2fs", action, elapsed)
    return data


def _profile_payload(session: Any, flow: str) -> dict:
    """把 turb 的 browser_profile 翻译成协议 JS 认得的入参。

    键名两边不一样（turb 用 navigator_language / timezone_iana，协议机用 language / timezone），
    这里集中做映射，别在调用点散落。
    """
    p = dict(getattr(session, "browser_profile", None) or {})
    device_id = str(getattr(session, "device_id", "") or "")

    langs = p.get("navigator_languages") or []
    if isinstance(langs, str):
        langs = [x.strip() for x in langs.split(",") if x.strip()]
    lang_primary = str(p.get("navigator_language") or (langs[0] if langs else "en-US"))
    if not langs:
        langs = [lang_primary]

    # 协议机按 UA 推断 platform/vendor；turb 的画像里已经有权威值，优先用它。
    payload = {
        "device_id": device_id,
        "flow": flow,
        "user_agent": str(p.get("user_agent") or ""),
        "screen_width": str(p.get("screen_width") or "1920"),
        "screen_height": str(p.get("screen_height") or "1080"),
        "language": lang_primary,
        "languages": list(langs),
        "platform": str(p.get("navigator_platform") or ""),
        "vendor": p.get("navigator_vendor"),
        "hardware_concurrency": int(p.get("hardware_concurrency") or 8),
        "browser_type": str(p.get("browser_family") or ""),
        "device_pixel_ratio": float(p.get("device_pixel_ratio") or 1.0),
        "max_touch_points": int(p.get("max_touch_points") or 0),
        # IANA 名原样透传；协议 JS 自己会做 ICU 规范化（Asia/Ho_Chi_Minh -> Asia/Saigon）
        "timezone": str(p.get("timezone_iana") or "UTC"),
    }
    mem = p.get("navigator_device_memory") or p.get("device_memory")
    if mem:
        payload["device_memory"] = int(mem)
    return payload


def request_p(session: Any, flow: str) -> str:
    """第一趟：出 request_p。这个 p 要原样交给 /sentinel/req。"""
    payload = _profile_payload(session, flow)
    data = _run_action("requirements", payload, _REQUIREMENTS_TIMEOUT)
    p = str(data.get("request_p") or "").strip()
    if not p:
        raise RuntimeError(f"协议 Sentinel requirements 未返回 request_p: {data}")
    logger.info("[SentinelProto] request_p 就绪 len=%d prefix=%s", len(p), p[:8])
    return p


def solve(session: Any, flow: str, challenge: dict, req_p: str) -> tuple:
    """第三趟：出最终 token 和 so_token。返回 (token, so_token)。"""
    if not req_p:
        raise ValueError("solve 需要 request_p（就是发给 /sentinel/req 的那个 p）")
    payload = _profile_payload(session, flow)
    payload.update({
        "request_p": str(req_p),
        "challenge": challenge,
        "flow": flow,
        "behavior_duration_ms": _BEHAVIOR_MS,
    })
    data = _run_action("solve", payload, _SOLVE_TIMEOUT)

    token = str(data.get("token") or "").strip()
    so_token = str(data.get("so_token") or "").strip()
    if not token:
        raise RuntimeError(f"协议 Sentinel solve 未返回 token: {str(data)[:300]}")

    if data.get("fallback"):
        # 回退分支：SDK 主路径没出 token，走的是 __debug_n 手算。
        # 这仍然能出 token，但说明 SDK 那条路没走通 —— 要响亮，别静默。
        logger.warning(
            "[SentinelProto] solve 走了 **回退分支**（SDK 主路径未出 token），"
            "token len=%d。这通常意味着 hook 或 SDK 版本变了。",
            len(token),
        )
    logger.info(
        "[SentinelProto] token 就绪 len=%d so=%s fallback=%s",
        len(token), len(so_token) or "无", bool(data.get("fallback")),
    )
    return token, (so_token or None)


def selftest() -> int:
    """零成本自检：只跑 requirements（不发 /sentinel/req、不注册、不消耗邮箱）。"""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    _ensure_files()
    print(f"引擎      : {engine()}")
    print(f"协议 JS   : {_JS_PATH} ({_JS_PATH.stat().st_size} B)")
    print(f"sdk.js    : {_SDK_PATH} ({_SDK_PATH.stat().st_size} B)")
    print(f"node      : {_node_bin()}")

    class _FakeSession:
        device_id = "00000000-0000-4000-8000-000000000000"
        browser_profile = {
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
            ),
            "navigator_language": "vi-VN",
            "navigator_languages": ["vi-VN", "vi", "en"],
            "navigator_platform": "Win32",
            "navigator_vendor": "Google Inc.",
            "screen_width": 1680,
            "screen_height": 1050,
            "hardware_concurrency": 6,
            "device_memory": 8,
            "device_pixel_ratio": 2,
            "timezone_iana": "Asia/Ho_Chi_Minh",
        }

    try:
        p = request_p(_FakeSession(), "email_otp_validate")
    except Exception as exc:
        print("FAIL:", type(exc).__name__, str(exc)[:400])
        return 1
    print(f"request_p : len={len(p)} prefix={p[:8]} head={p[:60]}")
    print("OK（第一趟通过；第二/三趟需要真 challenge，跑 _probe/sentinel_diag.py）")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
