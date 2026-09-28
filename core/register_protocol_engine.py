# -*- coding: utf-8 -*-
"""turb 的协议注册引擎 —— 直接驱动 vendored 的协议注册机。

设计
----
turb 原来那套协议注册（\`main.py\` 里一长串步骤 + \`core/openai_auth.py\` 的
network_preflight / follow_authorize / create_account ...）**已停用**，改成把活交给
协议机自己的 \`AuthFlow.run_register()\`。

为什么走子进程而不是直接 import
------------------------------
turb 根目录有 \`config\` 包，协议机也有 \`config.py\`；同进程 import 必撞名。
让协议机在自己的目录里跑（cwd + sys.path[0] 都是它），两边互不污染，
也不用给任何模块改名。桥接脚本：\`vendor/gpt-register-tool/协议/_turb_bridge.py\`。

对外接口
--------
    register(email, relay_url, proxy=None, ...) -> dict
        {"ok": True,  "partial": bool, "result": {email, password, access_token,
                                                  session_token, refresh_token,
                                                  cookie_header, totp_secret, ...}}
        {"ok": False, "error": "..."}

    check(email, relay_url, proxy=None) -> dict     零成本自检（只探代理，不注册）

引擎开关
--------
\`REGISTRATION_ENGINE\`：protocol（默认）/ legacy（turb 老流程）。
显式写在代码里，不动 \`.env\`。
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_PROTO_DIR = _PROJECT_ROOT / "vendor" / "gpt-register-tool" / "协议"
_BRIDGE = _PROTO_DIR / "_turb_bridge.py"

DEFAULT_ENGINE = "protocol"
_REGISTER_TIMEOUT = int(os.environ.get("PROTOCOL_REGISTER_TIMEOUT", "900"))
_CHECK_TIMEOUT = int(os.environ.get("PROTOCOL_CHECK_TIMEOUT", "120"))


def engine() -> str:
    return (os.environ.get("REGISTRATION_ENGINE", "") or "").strip().lower() or DEFAULT_ENGINE


def use_protocol() -> bool:
    return engine() != "legacy"


def _python_bin() -> str:
    return (os.environ.get("PROTOCOL_PYTHON_PATH", "") or "").strip() or sys.executable


def _ensure_bridge() -> None:
    if not _BRIDGE.exists():
        raise FileNotFoundError(
            f"找不到协议桥: {_BRIDGE}\n"
            "它应该随 vendor/gpt-register-tool/协议/ 一起进来。"
        )


def _run_bridge(job: dict, timeout: int) -> dict:
    _ensure_bridge()
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    # 协议机自己读这些环境变量决定出口与指纹
    if job.get("proxy"):
        env["PROXY"] = str(job["proxy"])
    if job.get("proxy_pool"):
        env["PROXY_POOL"] = str(job["proxy_pool"])
    if job.get("country"):
        env["FINGERPRINT_COUNTRY"] = str(job["country"])
    env.setdefault("FINGERPRINT_BROWSER_FAMILY", str(job.get("browser_family") or "auto"))

    try:
        proc = subprocess.run(
            [_python_bin(), str(_BRIDGE)],
            input=json.dumps(job, ensure_ascii=False),
            text=True,
            encoding="utf-8",
            capture_output=True,
            # cwd 必须是协议机自己的目录 —— 这样它的 \`import config\` 拿到的是它自己那份
            cwd=str(_PROTO_DIR),
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"协议注册超时（>{timeout}s, mode={job.get('mode')}）") from exc
    except FileNotFoundError as exc:
        raise RuntimeError(f"未找到 Python 解释器: {_python_bin()}") from exc

    # 协议机的日志全在 stderr，原样转出来，方便 turb 的日志里看到完整链路
    for line in (proc.stderr or "").splitlines():
        line = line.strip()
        if line:
            logger.info("[协议机] %s", line)

    out = (proc.stdout or "").strip()
    if not out:
        raise RuntimeError(
            f"协议桥输出为空 (mode={job.get('mode')}, rc={proc.returncode})\n"
            f"stderr tail: {(proc.stderr or '').strip()[-600:]}"
        )
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"协议桥输出不是 JSON: {out[:300]}") from exc
    return data


def check(email: str, relay_url: str = "", proxy: Optional[str] = None,
          country: str = "", proxy_pool: str = "") -> dict:
    """零成本自检：构造对象 + 探代理。不创建邮箱、不注册、不消耗号。"""
    return _run_bridge(
        {
            "mode": "check",
            "email": email,
            "relay_url": relay_url,
            "proxy": proxy or "",
            "proxy_pool": proxy_pool or "",
            "country": country or "",
        },
        _CHECK_TIMEOUT,
    )


def register(email: str, relay_url: str, proxy: Optional[str] = None,
             country: str = "", proxy_pool: str = "",
             browser_family: str = "auto", want_2fa: bool = True) -> dict:
    """跑完整注册。返回 {"ok", "partial", "result", "have"} 或 {"ok": False, "error"}。

    ⚠️ want_2fa 默认 True：协议机的 2FA 绑定是**选做**的
    （registrar 里 \`if options.get("want_2fa")\`），不显式打开就拿不到 totp_secret。
    返回的 \`have\` 会告诉你三样关键产物各自拿到了没有：
    access_token / totp_secret / cookie_header。
    """
    job = {
        "mode": "register",
        "email": email,
        "relay_url": relay_url,
        "proxy": proxy or "",
        "proxy_pool": proxy_pool or "",
        "country": country or "",
        "browser_family": browser_family or "auto",
        "want_2fa": bool(want_2fa),
    }
    logger.info("[协议引擎] 开始注册 %s (proxy=%s)", email, "有" if proxy else "无")
    data = _run_bridge(job, _REGISTER_TIMEOUT)
    if data.get("ok"):
        d = data.get("result") or {}
        have = data.get("have") or {}
        logger.info(
            "[协议引擎] %s 完成 partial=%s access=len%d session=len%d refresh=len%d",
            email, bool(data.get("partial")),
            len(str(d.get("access_token") or "")),
            len(str(d.get("session_token") or "")),
            len(str(d.get("refresh_token") or "")),
        )
        logger.info(
            "[协议引擎] %s 产物：AT=%s 2FA=%s cookie=%s password=%s",
            email,
            "有" if have.get("access_token") else "**无**",
            "有" if have.get("totp_secret") else "**无**",
            "有" if have.get("cookie_header") else "**无**",
            "有" if str(d.get("password") or "") else "**无**",
        )
    else:
        logger.warning("[协议引擎] %s 失败: %s", email, str(data.get("error"))[:300])
    return data


if __name__ == "__main__":
    # 自检：python -m core.register_protocol_engine [email] [relay_url]
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    e = sys.argv[1] if len(sys.argv) > 1 else "probe@icloud.com"
    u = sys.argv[2] if len(sys.argv) > 2 else ""
    print(json.dumps(
        check(e, u, proxy=os.environ.get("PROXY") or "socks5h://127.0.0.1:11900"),
        ensure_ascii=False, indent=2,
    ))
