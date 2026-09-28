# -*- coding: utf-8 -*-
"""turb <-> 协议注册机 的桥。

**为什么要单独一个进程**：turb 根目录也有一个 \`config\` 包，协议机也有
\`config.py\`，同进程里 import 必撞名。让协议机在自己的目录里跑（cwd + sys.path[0]
都是这里），两边互不污染，也不用给任何模块改名。

⚠️ 入口选的是 \`webui.registrar\`，**不是** \`AuthFlow.run_register\`。
   裸跑 AuthFlow 会漏掉三样东西（这三样都在 registrar 层）：
     1) **2FA 绑定**  —— registrar 的 \`_bind_2fa_hook\` / \`_bind_2fa_via_api\`，
        受 options["want_2fa"] 控制，结果写进 result.totp_secret
     2) **cookie 头** —— \`d["cookie_header"] = full.get("cookie_header")\`
     3) **落库**      —— \`db.save_registered(d)\`（registered 表，含 password/totp/cookie）
   裸 AuthFlow 只给 access_token/session_token/refresh_token，其余全是空串。

用法（由 turb 的 core/register_protocol_engine.py 调用）：

    echo '<job json>' | python _turb_bridge.py

job JSON：
    mode           : "check" | "register"
    email / relay_url
    proxy / proxy_pool / country / browser_family
    want_2fa       : 默认 true

stdout 永远是一份 JSON；日志走 stderr。
"""
from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# ── ⛔ 先清掉 .env 里那批以 _proxy 结尾的变量 ────────────────────────────
# 2026-09-24 定位：这是「验证码永远收不到」的**真正**根因。
#
# CPython 的 urllib.request.getproxies() 是这么写的：
#     return getproxies_environment() or getproxies_registry()
# 也就是说 —— 只要环境变量里**有一个**以 _proxy 结尾的非空变量，
# getproxies_environment() 就返回非空 dict，**Windows 注册表里的代理永远不会被读到**。
#
# turb 的 .env 里恰好有好几个：
#     ROXY_UNLIMITED_PROXY / PLAN_CHECK_PROXY / TWOFA_PROXY / MAILTM_PROXY / TEMPMAILIO_PROXY
# 它们本意是各功能的专用代理，却把「系统代理发现」整个带偏了。后果：
#
#     系统代理（注册表 -> 127.0.0.1:10808）   0.9s / 10.0s / 12.1s / 18.0s   通
#     直连（无代理）                          20.2s -> _ssl.c:999 handshake timeout
#
# 这台机器**直连不到 ic-mail.tibosb.cloud**，必须借 10808 那条隧道。清掉这几个变量后
# getproxies() 回落到注册表，取件立刻正常。
#
# 手工在干净 shell 里问同一个取码地址一直是好的 —— 因为那个 shell 没有这些变量。
# 这就是为什么它看起来"像中继站挂了"，其实取件端一个请求都没发对。
#
# 想保留原样：TURB_KEEP_PROXY_ENV=1
if os.environ.get("TURB_KEEP_PROXY_ENV", "").strip() not in ("1", "true", "yes"):
    _dropped = [k for k in list(os.environ) if k.lower().endswith("_proxy")]
    for _k in _dropped:
        os.environ.pop(_k, None)
    if _dropped:
        sys.stderr.write("[bridge] 已清掉 %d 个 *_proxy 环境变量（否则 urllib 会跳过系统代理）: %s\n"
                         % (len(_dropped), ", ".join(sorted(_dropped))))


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stderr,
)

from config import Config  # noqa: E402

# ── ⛔ TLS impersonate 必须降级到 chrome131 ──────────────────────────────
# 2026-09-23 实测（4 个出口 IP 各测 16 个 impersonate 目标打 authorize/continue）：
#
#   chrome99/116/119/120/123/124/131   PASS（131 在 4/4 个 IP 上全过）
#   chrome133a                         BLOCK
#   chrome142 / chrome145 / chrome146   BLOCK ← 协议机原本用的就是 chrome146
#   safari17_0 BLOCK / safari18_0 PASS / firefox133 PASS / firefox144 BLOCK
#
# **同一 IP，唯一变量是 impersonate。** 也就是说 CF 已经能识别 curl_cffi 的
# 新版 chrome 模仿 —— 版本越新越像"假的"（真 Chrome 的握手细节 curl_cffi 追不上，
# 反而把新版本独有的特征暴露了）。
#
# 因果链（10 并发那轮 0/10 的根因）：
#   chrome146 被 CF 拦 -> authorize/continue 403 -> 注册密码失败
#   -> 回退 passwordless -> 409 -> 重发 OTP 返 200（假阳性）-> 静默丢信
#
# ⚠️ 改这个**不影响**声称的 Chrome 版本：UA / sec-ch-ua 仍是 152
#    （fingerprint.py 自己注释：TLS 画像本身不带版本号，服务端读不出 146）。
#    所以 chrome131 的 TLS + 152 的 UA 是安全组合。
#
# 从桥里打补丁而不是改 fingerprint.py —— 不动主人那份文件，且一行可回退。
# ⛔ 关键：TLS impersonate 与**声称的 Chrome 版本必须一致**。
#
# 2026-09-23 实测（同一个 200 端口池，随机取 IP，每组 8 次打 create-account/password）：
#
#     chrome142 + 声称 142   PASS 8/8    OOOOOOOO   <- 100%
#     chrome146 + 声称 146   PASS 1/8    ......O.   <- 12.5%
#     chrome136 + 声称 136   PASS 0/8    ........   <- 0%
#
# 而**主人改之前的原始版**（gpt-auto-register-simulated-qc-source.zip）里
# _CHROME_VERSIONS 正好是 chrome136 / chrome142 / chrome146，**版本一一对应**：
#     {"impersonate": "chrome136", "ver": "136", "full_ver": "136.0.0.0"}
#     {"impersonate": "chrome142", "ver": "142", "full_ver": "142.0.0.0"}
#     {"impersonate": "chrome146", "ver": "146", "full_ver": "146.0.0.0"}
# 主人后来为了让「声称的版本看起来像真机」把它改成了 152，于是 TLS 是 146/145
# 而 UA/sec-ch-ua 声称 152 —— **版本对不上，CF 一眼看出来**。
# 这就是「原始版能过 CF、改完过不去」的原因。
#
# ⛔ 2026-09-24 结论：**TLS 档位必须等于声称的版本，而声称的版本必须留在 152**。
#
# 这中间绕了两轮，两轮都错：
#
#   第一轮「把声称降到 142 去对齐 TLS」—— CF 过了 8/8，但**注册出来的号全部拿不到
#   Plus 试用**（check_coupon -> not_eligible）。原因见 fingerprint.py 自己的注释：
#   落后 6 个大版本的 Chrome 本身就是可疑信号，比 TLS/UA 版本不齐更致命。
#
#   第二轮「保持声称 152、TLS 停在 curl_cffi 的 146」—— 试用正常，但 CF 过不去。
#
# 根子在于 curl_cffi 0.16 的档位**最高只到 chrome146**，「TLS = 声称」最多只能做到
# 146。wreq 把档位提到 Chrome153 之后这个约束才消失。实测（每档 12 次，交错取样、
# 每次换一个出口端口）：
#
#     Chrome150  12/12     Chrome152  12/12     Chrome153  12/12
#     Chrome151  11/12     Chrome149   1/12
#
# 所以锁 chrome152 —— 与 fingerprint.py 里那份真机指纹（152.0.7977.83）完全对齐，
# TLS 与声称**同时**是 152，两个问题一起消掉。
_SAFE_IMPERSONATE = (os.environ.get("TURB_IMPERSONATE", "") or "chrome152").strip()
_SAFE_CLAIM_VER = (os.environ.get("TURB_CLAIM_VER", "") or "").strip()   # 留空 = 不动声称版本


def _apply_safe_impersonate():
    """只把 TLS 档位对齐到声称的版本，**不改声称的版本本身**。

    为什么不改：fingerprint.py 里的 152 / 152.0.7977.83 / platform_version 15.0.0
    是照 Roxy 真机（Chrome 152）抄下来的，是这套指纹里最值钱的部分 —— 动它就是
    「第一轮」那个错误。这里只改 impersonate 一个字段。
    """
    try:
        import fingerprint as _fp
    except Exception as exc:
        sys.stderr.write("[bridge] 加载 fingerprint 失败，跳过 TLS 档位对齐: %s\n" % exc)
        return
    n = 0
    for v in getattr(_fp, "_CHROME_VERSIONS", []) or []:
        if not isinstance(v, dict):
            continue
        if _SAFE_CLAIM_VER:
            v["ver"] = _SAFE_CLAIM_VER
            v["ua_ver"] = _SAFE_CLAIM_VER + ".0.0.0"
        v["impersonate"] = _SAFE_IMPERSONATE
        n += 1
    # ⚠️ Safari / Firefox 那几档**不动** —— wreq 的 Safari18 / Firefox133 画像各自
    #    自洽，把 Safari 的 UA 配上 Chrome 的 TLS 反而更假。协议机本来就锁了
    #    fingerprint_browser_family="chrome"，那几档根本不会被选中。
    _vers = getattr(_fp, "_CHROME_VERSIONS", None) or [{}]
    ver = _vers[0].get("ver", "?")
    sys.stderr.write(
        "[bridge] TLS 档位已对齐: impersonate=%s / 声称=%s（改了 %d 条 chrome 档）\n"
        % (_SAFE_IMPERSONATE, ver, n)
    )

_apply_safe_impersonate()

# ── 中继取件超时：20s 根本不够，得提到 60s ──────────────────────────────
# ⛔ 2026-09-24 定位到的「验证码永远收不到」真因。
#
# 症状：跑批时**每一轮**取件都报
#     [icloud_relay] 拉取邮件异常（吞掉重试）: <urlopen error _ssl.c:999: The handshake operation timed out>
# 而手工问同一个取码地址却好好的。把两条路分开量（同一个 URL）：
#
#     走系统代理（Windows 注册表里指向 127.0.0.1:10808）
#         0.9s / 10.0s / 12.1s / 18.0s      <- 通，但**慢得离谱**
#     直连（ProxyHandler({})）
#         20.2s -> _ssl.c:999 handshake timeout   <- 完全不通
#
# 也就是说这台机器**直连不到 ic-mail.tibosb.cloud**，必须借 10808 那条隧道；
# 而 10808 本身又慢，正常要 10~18s。协议机默认 timeout=20 正好卡在刀口上，
# 再叠上 5~10 个号并发轮询，就**每次都超时**。
#
# 后果极具迷惑性：请求都发出去了、服务端也把码送到了（实测 city.briefer-5x
# 08:36 发码，08:47 码 391890 就躺在取码地址上），但取件端一个都读不到，
# 于是全部判「OTP 超时 180s」，号却已经建出来了。
#
# 修法：把中继取件的超时提到 60s（TURB_RELAY_TIMEOUT 可调）。补在**类**上而不是
# 调用点 —— registrar 是走 create_mail_provider 造的，补调用点会漏。
try:
    from mail_providers.icloud_relay import ICloudRelayProvider as _IRP

    _RELAY_TIMEOUT = int(os.environ.get("TURB_RELAY_TIMEOUT", "60") or 60)
    _irp_init = _IRP.__init__

    def _irp_init_patched(self, email, relay_url, timeout=20, *a, **kw):
        _irp_init(self, email, relay_url, max(int(timeout or 0), _RELAY_TIMEOUT), *a, **kw)

    _IRP.__init__ = _irp_init_patched
    sys.stderr.write("[bridge] 中继取件超时已提到 %ds（原来 20s 会被 10808 隧道拖死）\n" % _RELAY_TIMEOUT)
except Exception as _exc:
    sys.stderr.write("[bridge] 中继超时补丁失败: %s\n" % _exc)

# ── sentinel token 复用（流量实验，默认关）────────────────────────────
# ⛔ /sentinel/req 一次 **81 KiB**（协议机自己的注释：so 58 + turnstile 21），
#    每个号调 3 次（username_password_create / email_otp_validate /
#    oauth_create_account）= **188 KiB，占单号 326.9 KiB 的 58%**。
#    真机抓包是 10 次（每个敏感步骤前都新算一个），我们已经是精简过的。
#
#    复用成 1 次能直接省 ~125 KiB -> 200 KiB 上下。
#
#    ⚠️ 风险：服务端可能按 flow 校验 token，复用了会被拒（409/400）。
#    所以默认**关**，只有 TURB_SENTINEL_REUSE=1 时才装。跑 1 个号就能验。
#
#    实现方式：auth_flow 里是「from sentinel import get_sentinel_token」（函数内导入），
#    每次调用都重新查模块属性 —— 所以补在 sentinel 模块上就够，不用动 auth_flow。
def _install_sentinel_reuse():
    if os.environ.get("TURB_SENTINEL_REUSE", "").strip() not in ("1", "true", "yes"):
        return
    try:
        import sentinel as _S
    except Exception as exc:
        sys.stderr.write("[bridge] sentinel 复用补丁失败: %s\n" % exc)
        return
    _orig = getattr(_S, "get_sentinel_token", None)
    if _orig is None or getattr(_orig, "_turb_reuse", False):
        return
    _box = {}

    def _patched(session, device_id=None, flow="", **kw):
        f = str(flow or "")
        if f in ("email_otp_validate", "oauth_create_account") and _box.get("token"):
            sys.stderr.write("[bridge] sentinel 复用: flow=%s 直接用上一个 token（省 81 KiB）\n" % f)
            return _box["token"], _box.get("so", "")
        tok, so = _orig(session, device_id=device_id, flow=flow, **kw)
        _box["token"], _box["so"] = tok or "", so or ""
        return tok, so

    _patched._turb_reuse = True
    _S.get_sentinel_token = _patched
    sys.stderr.write("[bridge] sentinel token 复用已开启（email_otp_validate / oauth_create_account 复用）\n")


_install_sentinel_reuse()

# ── HTTP 层换成 wreq ────────────────────────────────────────────────────
# ⚠️ 必须在任何 from auth_flow import AuthFlow **之前**装 —— auth_flow 是
#    from http_client import create_http_session 拿的函数对象，装晚了它手里
#    还是旧引用（install() 会顺手把已导入模块里的绑定一起换掉）。
try:
    import http_client_wreq as _wreq_backend
    _WREQ_ON = _wreq_backend.install()
except Exception as _exc:
    _WREQ_ON = False
    sys.stderr.write("[bridge] wreq 后端装载失败，继续用 curl_cffi: %s\n" % _exc)
from mail_providers.icloud_relay import ICloudRelayProvider  # noqa: E402


def _emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False))
    sys.stdout.flush()


def _check(job: dict) -> int:
    """零成本自检：只构造对象 + 探代理，不创建邮箱、不注册。"""
    email = str(job.get("email") or "").strip()
    relay_url = str(job.get("relay_url") or "").strip()
    cfg = Config()
    cfg.proxy = str(job.get("proxy") or "").strip() or None
    try:
        mail = ICloudRelayProvider(email=email, relay_url=relay_url) if relay_url else None
    except Exception as exc:
        _emit({"ok": False, "error": f"ICloudRelayProvider 构造失败: {exc}"})
        return 1
    from auth_flow import AuthFlow
    flow = AuthFlow(cfg)
    try:
        proxy_ok = bool(flow.check_proxy())
    except Exception as exc:
        _emit({"ok": False, "error": f"check_proxy 异常: {exc}"})
        return 1
    _emit({"ok": True, "result": {
        "mode": "check", "proxy": cfg.proxy, "proxy_ok": proxy_ok,
        "mail_provider": getattr(mail, "kind", None) if mail else None,
        "flow_ready": hasattr(flow, "run_register"),
    }})
    return 0


# ── IP 探测与轮换 ────────────────────────────────────────────────────────
# 为什么需要：CF 的拦截是**按出口 IP**的，而这个代理池每个 sid 是独立粘性会话
# （用户名里 _time_10 = 10 分钟），所以「哪个端口干净」**会随时间变** —— 现在扫出来的
# 白名单十分钟后就作废。实测：同一个端口 11986 在并发探针里是 CF-BLOCK，
# 几分钟后单独打它却是 200。
#
# 所以正确做法不是"提前建白名单"，而是**用前先探、不通就换**。
# 换一个端口 = 换一个出口 IP（不同 sid），池子里 100 个，总有干净的。
#
# ⚠️ 协议机自带的 warmup() 是**在同一个 IP 上重试 20 次** —— 那个 IP 已经被 CF
#    标记了，重试到天亮也没用，还拖慢几分钟。这里在外面换 IP，不动它的代码。

# ⛔ 2026-09-24 修：原来的 "challenge-platform" 是**误报源**，而且代价极大。
#
#    真机上**每一个正常页面**都带这段 CF 的非交互式 JS 探测（JSD）引导脚本：
#        var a=document.createElement('script');
#        a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js';
#    于是一个 200 / 63.9 KiB 的健康 create-account/password 页面被判成"被 CF 拦"：
#        _probe_grade 永远返回 1（半通过）
#        -> _pick_clean_proxy 找不到 grade 2，把 14 个出口**全探一遍**才退回
#        -> 单号白烧 ~4.5 MiB 探测流量，比注册本身还贵（这就是"流量爆炸"的真因）
#
#    真正的挑战页面走的是 /cdn-cgi/challenge-platform/h/ 这个路径，标题是
#    "Just a moment..."，或者直接 403。所以标记改成下面这组精确串。
_CF_MARKERS = ("just a moment", "challenge-platform/h/", "cf-chl-", "__cf_chl")


_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36")

# ⚠️ 必须探**两个**端点，只探 chatgpt.com 会放过脏 IP。
#
# 2026-09-23 实测（10 并发那轮）：只探 chatgpt.com/api/auth/csrf 时，12 个出口
# 探针判"干净"，但真跑起来 authorize/continue 撞了 8 次 CF 403，因果链是：
#     authorize/continue 403 -> 注册密码失败 -> 回退 passwordless -> 409
#     -> 重发 OTP 返回 200（**假阳性**）-> 信永远不到 -> OTP 超时 180s
# 也就是说：**CF 对 auth.openai.com 的保护比 chatgpt.com 严**，
# 只探后者等于放行了一批在真正关口上会被拦的 IP，10 个号全废。
def _probe_proxy(proxy: str, timeout: int = 20) -> bool:
    """兼容旧签名：能过 chatgpt.com 就算 True。"""
    return _probe_grade(proxy, timeout) >= 1


def _probe_grade(proxy: str, timeout: int = 20) -> int:
    """0=chatgpt.com 就过不了；1=只过 chatgpt.com；2=两个端点都过。"""
    try:
        # ⚠️ 探针必须和真跑**用同一套 HTTP 栈**，否则探针的结论对真跑没有预测力。
        #    curl_cffi 时代就吃过这个亏：探针说干净，真跑却在 create-account/password
        #    被 403 —— 两边的 TLS 指纹根本不是同一个。
        from http_client import create_http_session
        s = create_http_session(proxy=proxy, impersonate=_SAFE_IMPERSONATE, user_agent=_UA)
        h = {"user-agent": _UA, "accept": "application/json", "referer": "https://chatgpt.com/"}

        r = s.get("https://chatgpt.com/api/auth/csrf", headers=h, timeout=timeout)
        if r.status_code != 200:
            return 0
        b = (r.text or "").lower()
        if any(m in b for m in _CF_MARKERS) or "csrftoken" not in b:
            return 0

        # ⚠️ 真正的关口是 create-account/password 这个**页面**，不是 authorize/continue。
        # 2026-09-23 实测：只探 authorize/continue 时判"双通过"，真跑起来
        #   [5.5/10] 注册密码 -> create-account/password 页面: 403（CF）
        #   -> 密码注册 409 invalid_state -> 注册密码失败 -> 回退 passwordless
        #   -> 409 -> 重发 OTP 返 200（假阳性）-> 静默丢信
        # 也就是说：**关口会换**，探针必须跟着走。这里把两个都探，任一被 CF 拦就降级。
        # ⚠️ 单次探测不够 —— 一次注册要发 ~28 个请求，CF 是在**过程中**累积评分后
        # 才开始拦的。2026-09-23 实测：探针 2 秒打 3 个请求判"双通过 11/11"，
        # 真跑却有 7 个在 create-account/password 被 403 —— **冷启动干净的 IP
        # 跑到一半就掉下去了**。所以这里改成压力探测：连打 N 次，全过才算干净。
        #
        # 不是"降速"，是**挑有余量的 IP** —— 池子里 100 个，高并发要的就是把
        # 抗得住的挑出来，而不是让所有 IP 都慢下来。
        # ⚠️ 2026-09-24：默认从 5 轮降到 2 轮。**每轮 = 一整页 create-account/password
        #    （实测 ~64 KiB）**，而 5 轮探针 × 最多 14 个出口 = 单号 4.5 MiB 纯探测流量，
        #    比注册本身还贵。wreq 之后 IP 的过闸率已经到 12/12，压力探测的边际收益
        #    撑不起这个成本。
        # ⛔ 2026-09-24 再降：默认 1 轮，且**允许 0**（0 = 完全跳过页面探测）。
        #
        # 流量实测拆解（40 个号均值，单号合计 377 KiB）：
        #     POST sentinel.openai.com/backend-api/sentinel/    166.4 KiB  (2.7 次)
        #     GET  auth.openai.com/create-account/password      158.2 KiB  (3.0 次)  <-- 这里
        #     其它全部                                            53 KiB
        #
        # 那 3 次页面 GET = 探针 2 轮 + register_password 自己 1 次，每次 ~53 KiB。
        # wreq 之后过闸率已经 12/12，压力探测的边际收益远撑不起 106 KiB/号。
        # 设 0 就只剩 register_password 那一次 —— 反正它自己也会在拿到 CF 页时判失败。
        try:
            rounds = int(os.environ.get("TURB_PROBE_ROUNDS", "1") or 0)
        except Exception:
            rounds = 1
        for _i in range(max(0, rounds)):
            try:
                rp = s.get(
                    "https://auth.openai.com/create-account/password",
                    headers={"user-agent": _UA,
                             "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                             "referer": "https://auth.openai.com/"},
                    timeout=timeout,
                )
            except Exception:
                return 1
            bp = (rp.text or "").lower()
            if any(m in bp for m in _CF_MARKERS) or rp.status_code == 403:
                return 1

        # authorize/continue 是**兜底探测**，被拦不致命，但仍算负信号。
        # 假邮箱即可 —— 服务端只会回 409 JSON，不建号。
        r2 = s.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={
                "user-agent": _UA,
                "accept": "*/*",
                "content-type": "application/json",
                "origin": "https://auth.openai.com",
                "referer": "https://auth.openai.com/create-account",
            },
            json={"username": {"value": "probe@example.com", "kind": "email"}, "screen_hint": "signup"},
            timeout=timeout,
        )
        b2 = (r2.text or "").lower()
        _ac_cf = any(m in b2 for m in _CF_MARKERS) or r2.status_code == 403
        if _ac_cf:
            # ⛔ 这里**不再降级** —— authorize/continue 的 403 是常态（这个端点被 CF
            #    看得比页面还严），把它当门槛的结果是 **grade 2 永远拿不到**，
            #    于是 _pick_clean_proxy 每次都把 14 个出口全探一遍才退回 grade 1，
            #    单号白烧 4.5 MiB。协议机自己的注释也写着这个端点"19.8MB 抓包里 0 命中"，
            #    邮箱是靠 signin 的 login_hint 送达的。所以只记录，不判负。
            sys.stderr.write("[bridge] 提示: authorize/continue 被拦（不致命，仅记录）\n")
        return 2
    except Exception:
        return 1 if proxy else 0


def _candidate_proxies(job: dict) -> list:
    """候选出口列表：显式 proxy 优先，然后是 proxy_pool / PROXY_POOL。"""
    out = []
    one = str(job.get("proxy") or "").strip()
    if one:
        out.append(one)
    for raw in (str(job.get("proxy_pool") or ""), os.environ.get("PROXY_POOL", "")):
        for line in str(raw).replace(",", "\n").splitlines():
            line = line.strip()
            if line and line not in out:
                out.append(line)
    return out


# ── 出口使用台账：优先挑「我们最久没用过」的出口 ──────────────────────
# 为什么要这个：0 元率主要看出口 IP 的"冷热"，不是看 TLS。而出口池是 100 个
# 粘性端口（用户名里 _time_10 = 10 分钟），**刚被我们跑过一堆号的 IP 再拿来注册，
# 优惠命中率明显低**。旧做法是随机 shuffle 后取第一个过闸的 —— 大概率撞上热 IP。
#
# 这里记一份本地台账（端口 -> 上次使用时间戳），挑的时候**按最久没用排序**，
# 只探 1~2 个就收。流量跟"随机取一个"一样低，但冷 IP 概率大幅提高。
# 台账放在临时目录，跑批之间共享；文件坏了/丢了就当全是冷的，不影响主流程。
_LEDGER_PATH = None


def _ledger_path():
    global _LEDGER_PATH
    if _LEDGER_PATH is None:
        import tempfile
        _LEDGER_PATH = os.path.join(tempfile.gettempdir(), "turb_exit_ledger.json")
    return _LEDGER_PATH


def _ledger_load() -> dict:
    try:
        with open(_ledger_path(), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _ledger_touch(proxy: str) -> None:
    try:
        import time as _t
        d = _ledger_load()
        d[str(proxy)] = _t.time()
        # 只留最近 400 条，别让文件无限长
        if len(d) > 400:
            for k in sorted(d, key=lambda x: d.get(x) or 0)[:len(d) - 400]:
                d.pop(k, None)
        p = _ledger_path()
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(tmp, p)
    except Exception:
        pass


def _pick_clean_proxy(job: dict, tried: set, max_probe: int = 6):
    """分级挑出口：优先「两个端点都过」的，没有再退回「只过 chatgpt.com」的。

    为什么分级：auth.openai.com 的 authorize/continue 在注册链路里只是**兜底探测**
    （协议机注释：19.8MB 抓包里它 0 命中，邮箱靠 signin 的 login_hint 送达），
    所以它被 CF 拦 ≠ 这个 IP 不能用 —— 实测严格双通过时 12 个出口**全不过**，
    那样工具直接没法用了。

    ⚠️ 2026-09-24 更正：它其实**不是**可靠信号 —— 见 _probe_grade 里的说明，
    它现在只记录、不降级。否则 grade 2 永远拿不到，每次都把 14 个出口探完。

    返回 (proxy, 探测个数)。
    """
    import random as _random
    cands = [p for p in _candidate_proxies(job) if p not in tried]
    # ⛔ 按「最久没用过」排序，而不是随机 —— 冷 IP 的 0 元率明显更高。
    #    同刻的用随机打破平局，避免所有 worker 抢同一个端口。
    _led = _ledger_load()
    cands.sort(key=lambda p: (_led.get(p, 0.0), _random.random()))
    cands = cands[:max_probe]
    n = 0
    fallback = None
    for p in cands:
        n += 1
        grade = _probe_grade(p)
        tried.add(p)
        _ledger_touch(p)
        if grade == 2:
            sys.stderr.write("[bridge] 出口可用(双通过) %s（探了 %d 个）\n" % (p, n))
            return p, n
        if grade == 1:
            if fallback is None:
                fallback = p
                sys.stderr.write("[bridge] 出口半通过(仅 chatgpt.com)，先留着: %s\n" % p)
        else:
            sys.stderr.write("[bridge] 出口被 CF 拦，换下一个: %s\n" % p)
    if fallback:
        sys.stderr.write("[bridge] 没有双通过的，退回半通过: %s（共探 %d 个）\n" % (fallback, n))
        return fallback, n
    return None, n


def _account_created_from_log(log_file) -> bool:
    """从 run 日志判断**账号到底建出来没有** —— 决定能不能换 IP 重试。

    为什么不能只看错误字符串：OTP 超时有两种完全不同的成因，
      (a) 注册密码成功 -> 账号已建 -> 换 IP 重试会白烧邮箱  -> 不可重试
      (b) 注册密码失败 -> 账号没建 -> 换 IP 重试完全安全    -> 可重试
    两者的**表面错误都是「iCloud 中转 OTP 超时 180s」**，只看错误串会把 (b) 误判成
    不可重试，白白丢掉一个还能救的邮箱。2026-09-23 实测：10 并发那轮 7 个 OTP 超时
    里全部是 (b)（日志里 8 次「注册密码失败」、0 次「该号已生成密码」）。

    判据（协议机自己的日志原文，不猜）：
      「该号已生成密码」= 明确已建号
      「注册密码失败」  = 明确没建号
    """
    if not log_file:
        return True  # 读不到就保守当成已建，别烧邮箱
    try:
        from pathlib import Path as _P
        p = _P(str(log_file))
        if not p.exists():
            return True
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return True
    if "该号已生成密码" in text:
        return True
    if "注册密码失败" in text:
        return False
    # 日志里既没有建号证据也没有失败证据 —— 保守
    return True


def _is_retryable_before_account(err: str) -> bool:
    """只有**账号创建之前**的失败才能重试 —— 否则重试会把邮箱烧掉。

    能重试：warmup 挂 / CF 拦 / 环境分配失败 / 出口不通
    不能重试：OTP 超时（账号已建、密码已生成）、invalid_auth_step（OpenAI 侧已有号）
    """
    e = str(err or "").lower()
    if "otp" in e or "验证码" in e or "invalid_auth_step" in e or "该号已生成密码" in e:
        return False
    return any(k in e for k in (
        "warmup", "just a moment", "403", "环境", "environmentallocation",
        "出口", "connection", "timeout", "ssl", "socks", "cf",
    ))


# ── ③ 跨进程启动节流 ────────────────────────────────────────────────────
# 为什么需要：10 个 worker 同时开跑时，OTP 派发请求也会挤在一起，实测 OpenAI 会
# **静默丢掉一部分**（取件链接事后查仍是 no_code，信根本没发）。
#   5 并发 -> 3/5 = 60%
#   10 并发 -> 2/10 = 20%
# 不是 IP 问题（10 个 IP 全不同、全双通过），是**时间窗口**上的批量。
# 这里用文件锁做跨进程限速：两次注册的**启动**之间至少隔 N 秒，
# 因为 OTP 在启动后约 30~60s 发出，错开启动就等于错开发码。
# 环境变量 TURB_START_GAP 调（默认 8 秒；0 = 关掉）。

# ── 混合模式：CF 把门的 GET 交给真浏览器发 ─────────────────────────────
# 为什么可行（2026-09-23 实测日志）：
#     create-account/password 页面: 403        <- CF 拦的是这个 **GET**
#     密码注册返回 409: invalid_state          <- 紧接着的 POST **通了**（业务层响应）
#   也就是说 POST 本身不过 CF，坏在 GET 被拦后会话状态没建立。
#   真 Chrome 在**同一个 IP** 上能过（实测拿到 cf_clearance 并通过 authorize/continue）。
#
# 为什么不能只采 cookie：cf_clearance 绑定 TLS/JA4 指纹，注入 curl_cffi 无效（实测）。
#   -> 必须让**浏览器自己去发那个请求**。但浏览器发完种下的**普通会话 cookie**
#      是可以带回 curl_cffi 的（只有 cf_clearance 不行）。
#
# 所以：把 curl_cffi 已有的 cookie 灌进浏览器 -> 浏览器导航那个页面 -> 把新 cookie 拿回来。

_GATE_URL = "https://auth.openai.com/create-account/password"


def _browser_pass_gate(flow) -> bool:
    """用真浏览器过 create-account/password 那道闸，cookie 双向搬运。"""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        sys.stderr.write("[bridge] 没有 playwright，跳过浏览器过闸: %s\n" % exc)
        return False
    proxy = str(getattr(flow.config, "proxy", "") or "").strip()
    if not proxy:
        return False
    pw_proxy = proxy.replace("socks5h://", "socks5://")   # Chrome 不认 socks5h
    ua = str(getattr(flow, "_ua", "") or "").strip()
    # ⛔ 2026-09-24 修：Playwright 的 add_cookies 对字段很挑，
    #    原来这里只过滤了 name，于是 domain 为空 / 值含非法字符的 cookie
    #    会让**整批**注入失败：
    #        BrowserContext.add_cookies: Protocol error (Storage.setCookies):
    #        Invalid cookie fields
    #    注入失败 = 浏览器**没带会话 cookie** 去开页面 = 拿回来的是另一个会话的
    #    cookie，等于白跑一趟。实测那一轮就是这么废的（密码注册返回 400）。
    #    这里逐条校验：name/value 非空、domain 必须像域名、value 里不能有控制字符。
    ck_in = []
    try:
        for c in list(flow.session.cookies):
            name = str(getattr(c, "name", "") or "").strip()
            value = str(getattr(c, "value", "") or "")
            if not name or not value:
                continue
            if any(ord(ch) < 32 for ch in name + value):
                continue
            dom = str(getattr(c, "domain", "") or "").strip()
            if not dom or "." not in dom:
                dom = ".openai.com"
            if not dom.startswith("."):
                dom = "." + dom
            ck_in.append({"name": name, "value": value, "domain": dom,
                          "path": str(getattr(c, "path", "") or "/") or "/"})
    except Exception:
        ck_in = []

    got = {}
    try:
        with sync_playwright() as pw:
            br = pw.chromium.launch(headless=True, args=["--no-sandbox"])
            ctx_kw = {"proxy": {"server": pw_proxy}, "locale": "vi-VN", "timezone_id": "Asia/Ho_Chi_Minh"}
            if ua:
                ctx_kw["user_agent"] = ua
            ctx = br.new_context(**ctx_kw)
            if ck_in:
                # 逐条加，一条坏的不要拖垮整批
                _ok = 0
                for _ck in ck_in:
                    try:
                        ctx.add_cookies([_ck])
                        _ok += 1
                    except Exception:
                        pass
                if _ok != len(ck_in):
                    sys.stderr.write("[bridge] cookie 灌进浏览器: %d/%d 成功（其余字段非法已跳过）\n"
                                     % (_ok, len(ck_in)))
                else:
                    sys.stderr.write("[bridge] cookie 灌进浏览器: %d 条全部成功\n" % _ok)
            page = ctx.new_page()
            r = page.goto(_GATE_URL, wait_until="domcontentloaded", timeout=60000)
            body = ""
            try:
                body = page.content()
            except Exception:
                pass
            blocked = ("Just a moment" in body) or (r is not None and r.status == 403)
            for c in ctx.cookies():
                got[c["name"]] = c["value"]
            br.close()
    except Exception as exc:
        sys.stderr.write("[bridge] 浏览器过闸异常: %s\n" % str(exc)[:140])
        return False

    if blocked:
        sys.stderr.write("[bridge] 浏览器也没过闸（CF 挑战）\n")
        return False
    # 把浏览器拿到的 cookie 写回 curl_cffi（cf_clearance 无效但无害，其余有效）
    n = 0
    for k, v in got.items():
        for dom in (".openai.com", "auth.openai.com", ".chatgpt.com"):
            try:
                flow.session.cookies.set(k, v, domain=dom)
                n += 1
            except Exception:
                pass
    sys.stderr.write("[bridge] 浏览器过闸成功，回灌 %d 个 cookie（共拿到 %d 个）\n" % (n, len(got)))
    return True


def _install_browser_gate():
    """给 AuthFlow.register_password 套一层：先让浏览器过闸，再走原逻辑。

    ⚠️ wreq 通了之后默认**关掉**：这层是 curl_cffi 过不了闸时的拐杖，每个号要多起
    一个 headless Chromium（2-3s + 一大坨流量），而 wreq 实测 12/12 直接过闸。
    要重新打开：TURB_BROWSER_GATE=1。
    """
    _default = "0" if _WREQ_ON else "1"
    if os.environ.get("TURB_BROWSER_GATE", _default).strip() in ("0", "false", "no"):
        return
    try:
        from auth_flow import AuthFlow
    except Exception as exc:
        sys.stderr.write("[bridge] 装浏览器过闸失败: %s\n" % exc)
        return
    if getattr(AuthFlow, "_turb_gate_patched", False):
        return
    _orig = AuthFlow.register_password

    def _patched(self, email):
        try:
            _browser_pass_gate(self)
        except Exception as exc:
            sys.stderr.write("[bridge] 过闸步骤异常，继续原逻辑: %s\n" % str(exc)[:140])
        return _orig(self, email)

    AuthFlow.register_password = _patched
    AuthFlow._turb_gate_patched = True
    sys.stderr.write("[bridge] 已装载浏览器过闸（create-account/password 走真 Chrome）\n")


def _start_slot():
    try:
        gap = float(os.environ.get("TURB_START_GAP", "8") or 0)
    except Exception:
        gap = 8.0
    if gap <= 0:
        return
    import tempfile, time as _t
    lock = os.path.join(tempfile.gettempdir(), "turb_reg_start.lock")
    stamp = os.path.join(tempfile.gettempdir(), "turb_reg_last_start")
    deadline = _t.time() + 600
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            break
        except FileExistsError:
            if _t.time() > deadline:
                return
            _t.sleep(0.3)
        except Exception:
            return
    try:
        last = 0.0
        try:
            last = float(open(stamp).read().strip())
        except Exception:
            pass
        wait = gap - (_t.time() - last)
        if wait > 0:
            sys.stderr.write("[bridge] 启动节流，等 %.1fs\n" % wait)
            _t.sleep(wait)
        open(stamp, "w").write(str(_t.time()))
    finally:
        try:
            os.unlink(lock)
        except Exception:
            pass


def _register(job: dict) -> int:
    from webui import db as pdb
    from webui import registrar

    email = str(job.get("email") or "").strip()
    relay_url = str(job.get("relay_url") or "").strip()
    if not email or not relay_url:
        _emit({"ok": False, "error": "register 模式需要 email 和 relay_url"})
        return 2

    pdb.init_db()
    # 号池来源：turb 走的是 iCloud 中转取件
    pdb.set_setting("mail_source", "icloud_relay")

    # 混合模式：让 create-account/password 那道 CF 闸由真浏览器来过
    _install_browser_gate()

    # ③ 跨进程启动节流（错开发码，避免 OpenAI 静默丢信）
    _start_slot()

    # ── ① 「账号已存在」走 OTP-login，而不是报 409 失败 ──────────────────
    # registrar 里这个开关的原文：
    #   _allow_login = self._get_env("WEBUI_ALLOW_LOGIN", "").strip() in ("1","true","yes")
    #   开了 -> 走 OTP login 拿凭证；没开 -> fast-fail 把号判死
    #
    # 为什么必须开：前面几轮失败（CF 那阵子）把账号建出来了但没拿到凭证，
    # 池子又把邮箱放回 available。再跑时 OpenAI 说「已注册」-> 409 -> 号被白扔。
    # 这些号**账号是好的**，只是我们手上没凭证 —— 走 OTP-login 就能救回来，
    # 不用重新注册，也不浪费邮箱。2026-09-23 实测 5/10 的失败是这个原因。
    os.environ.setdefault("WEBUI_ALLOW_LOGIN", "1")

    account = {"email": email, "relay_url": relay_url}

    max_ip_tries = int(os.environ.get("TURB_BRIDGE_MAX_IP_TRIES", "6"))
    tried: set = set()
    last_err = ""
    run_id = ""
    row = {}
    log_file = None
    probes_total = 0

    for attempt in range(1, max_ip_tries + 1):
        # ① 先探一个干净出口 —— 不通就换，别在一个被 CF 标记的 IP 上死磕
        proxy, nprobe = _pick_clean_proxy(job, tried)
        probes_total += nprobe
        if not proxy:
            last_err = (
                f"连续探了 {probes_total} 个出口都被 CF 拦或不通，"
                f"放弃（池子可能整体被标记，换供应商或等粘性会话轮换）"
            )
            break

        options = {
            "proxy": proxy,
            # ⛔ proxy_pool 必须给全量池，不能是空串！
            # auth_flow.py:160  self._proxy_pool = _pool or ([config.proxy] if config.proxy else [])
            # auth_flow.py:1883 _next_proxy(): 池子空就返回同一个 proxy
            #   -> warmup() 第 1974 行的"换出口 IP 重试"变成**原地重试**，等于没重试。
            # webui/environment.py:179 会从 options["proxy_pool"] 解析出池子传下去。
            # 这是我之前写成 "" 造成的 —— 协议机自带的 IP 轮换一直被我关着。
            "proxy_pool": "\n".join(_candidate_proxies(job)),
            "fingerprint_country": str(job.get("country") or ""),
            # ⛔ 必须锁死 chrome，不能用 "auto"。
            # 2026-09-23 实测：环境账本最近 14 次分配 browser_family **全是 firefox**，
            # impersonate 分布 firefox144 x9 / firefox133 x5 —— 而 CF 对这两个的态度是
            #     firefox133  PASS
            #     firefox144  BLOCK      ← 占了 64%
            # 也就是说不锁的话，一多半的号一开局就在被 CF 拦的指纹上跑，
            # 后面必然走 authorize/continue 403 -> 注册密码失败 -> 假阳性 OTP -> 静默丢信。
            # 锁 chrome 后配合 _SAFE_IMPERSONATE=chrome131，是 4/4 IP 全过的组合。
            "fingerprint_browser_family": "chrome",
            "browser_engine": "playwright",
            "want_access_token": True,
            "want_session_token": True,
            "want_refresh_token": True,
            "want_2fa": bool(job.get("want_2fa", True)),
            # ⛔ 2026-09-24：中继站的验证码是**迟到**的，180s 根本等不到。
            #
            # 实测（10 个全新号）：city.briefer-5x 08:36 发码 -> 08:39:05 判超时
            # -> 我 08:47 再去问取码地址，码 391890 就躺在那儿了 —— **迟了 8~11 分钟**。
            # 也就是说邮件确实到了，只是中继站同步 iCloud 太慢，而
            #     registrar.py:308  env_overrides["OTP_TIMEOUT"] = str(int(options.get("otp_timeout") or 180))
            # 只给 180s。结果整批号全卡在「该号已生成密码」，邮箱白烧。
            #
            # 注意：码在取码地址上只挂几分钟（city.briefer-5x 第一次问到、几分钟后再问就没了），
            # 所以超时**不能设太小**，设到 900s 让轮询一直挂着最稳。
            "otp_timeout": int(os.environ.get("TURB_OTP_TIMEOUT", "900") or 900),
        }

        sys.stderr.write("[bridge] 第 %d/%d 次尝试，出口=%s\n" % (attempt, max_ip_tries, proxy))
        try:
            run_id = registrar.start_registration(account, options)
        except Exception as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            sys.stderr.write("[bridge] 起链路失败：%s\n" % last_err[:200])
            if _is_retryable_before_account(last_err):
                tried.add(proxy)
                continue
            break

        # 协议机把每轮日志写在 webui/logs/<run_id>.log —— 后面要靠它判账号建没建
        try:
            log_file = registrar.LOG_DIR / (str(run_id) + ".log")
        except Exception:
            log_file = None

        # start_registration 起的是 daemon 线程；队列收到 None 表示这一轮结束
        # （见 registrar.QueueLogHandler.close 的约定）。
        q = registrar.get_run_queue(run_id)
        if q is not None:
            while True:
                try:
                    # 队列空闲超时必须**大于**协议机自己的 OTP 等待窗口，
                    # 否则等验证码那段时间一条日志都没有，队列 Empty 一抛，
                    # 桥就先于注册线程收工了 —— 然后拿 registered 表里那行
                    # 「密码已落盘（凭证待补）」当成功，报出一个 ok=False 且
                    # 没有 error 的结果，看起来像"未知错误"。
                    # 实测踩过：TURB_OTP_TIMEOUT=1800 而这里默认 900，
                    # 900s 一到就误判收工。
                    _idle = float(os.environ.get("TURB_BRIDGE_IDLE_TIMEOUT") or 0)
                    if _idle <= 0:
                        _idle = float(os.environ.get("TURB_OTP_TIMEOUT") or 1800) + 300.0
                    item = q.get(timeout=_idle)
                except Exception:
                    break
                if item is None:
                    break

        row = pdb.get_registered(email) or {}
        if row:
            sys.stderr.write("[bridge] 成功（第 %d 次尝试，共探了 %d 个出口）\n" % (attempt, probes_total))
            break

        # 失败：读 runs 表里的错误，判断能不能换 IP 重试
        last_err = ""
        try:
            rec = pdb._conn().execute(
                "select status, error from runs where run_id=? limit 1", (run_id,)
            ).fetchone()
            if rec:
                last_err = str(rec[1] or rec[0] or "")
        except Exception:
            pass
        if not last_err:
            last_err = "注册结束但 registered 表里没有这一行"

        # 先看日志判账号建没建 —— 比错误字符串准得多（见 _account_created_from_log）
        created = _account_created_from_log(log_file)
        if created:
            sys.stderr.write("[bridge] 日志显示**账号已建**，不换 IP 重试（免得白烧邮箱）：%s\n" % last_err[:160])
            break
        if not _is_retryable_before_account(last_err):
            sys.stderr.write("[bridge] 失败但**不能重试**（可能已建号/已烧邮箱）：%s\n" % last_err[:200])
            break
        sys.stderr.write("[bridge] 日志显示**账号没建**（注册密码失败），换 IP 重试：%s\n" % last_err[:160])
        sys.stderr.write("[bridge] 失败可重试，换 IP：%s\n" % last_err[:200])
        tried.add(proxy)

    if not row:
        _emit({"ok": False, "error": last_err or "未知失败",
               "run_id": run_id, "probes": probes_total})
        return 1

    d = dict(row)

    # ── 补 __Secure-next-auth.session-token ────────────────────────────────
    # 协议机的 _build_chatgpt_cookie_header 只遍历 session 的 cookie jar，
    # 而 session_token 是从 /api/auth/session 的响应里取的，**没落进 jar** ——
    # 所以导出的 cookie_header 里没有它。
    # 而 chatgpt.com 的浏览器登录态就是这条 cookie：
    #   webui/app.py:1092 "access_token 推不出浏览器 cookie
    #                      (__Secure-next-auth.session-token 只在…)"
    # 缺了它，turb 的「打开浏览器」注入 cookie 后是未登录状态。
    # 同域其它 cookie（csrf / oai-sc / oai-did …）保留，服务端会一起校验。
    _st = str(d.get("session_token") or "").strip()
    _ck = str(d.get("cookie_header") or "").strip()
    if _st and "__Secure-next-auth.session-token=" not in _ck:
        d["cookie_header"] = "__Secure-next-auth.session-token=" + _st + ("; " + _ck if _ck else "")
        sys.stderr.write("[bridge] cookie_header 已补 __Secure-next-auth.session-token\n")

    got_at = bool(str(d.get("access_token") or ""))
    got_2fa = bool(str(d.get("totp_secret") or ""))
    got_cookie = bool(str(d.get("cookie_header") or ""))

    # ── 流量 ────────────────────────────────────────────────────────────
    # 协议机的 http_client 一直在记账（TRAFFIC = {total, requests, by_key}），
    # 但它只活在这个子进程的内存里 —— 不取出来，父进程（turb）就永远看不到。
    # turb 的 WebUI 读的是 extra_json["network_traffic"]，键名必须对上
    # （webui/app.py:118）。turb 老流程用 BrowserSession.network_traffic_snapshot()，
    # 协议引擎没有 BrowserSession，所以从这里搬。
    traffic = {}
    try:
        from http_client import TRAFFIC
        by_key = {}
        for k, v in sorted((TRAFFIC.get("by_key") or {}).items(),
                           key=lambda kv: -(kv[1] or {}).get("bytes", 0))[:30]:
            by_key[k] = {"bytes": int((v or {}).get("bytes") or 0),
                         "requests": int((v or {}).get("n") or 0),
                         "body_in": int((v or {}).get("body_in") or 0),
                         "hdr_out": int((v or {}).get("hdr_out") or 0),
                         "body_out": int((v or {}).get("body_out") or 0)}
        # ⚠️ 键名必须跟前端对齐（webui/templates/index.html）：
        #    formatTraffic 要求 available=True 且读 request_count；
        #    formatTrafficSplit 同样先判 reg.available，否则整块显示 '-'。
        #    只给 total_bytes/requests 的话，库里数据是好的，页面上却是空的。
        total = int(TRAFFIC.get("total") or 0)
        reqs = int(TRAFFIC.get("requests") or 0)
        traffic = {
            "available": True,
            "total_bytes": total,
            "download_bytes": total,
            "upload_bytes": 0,
            "request_count": reqs,
            "requests": reqs,          # 兼容：有些地方读 requests
            "by_key": by_key,
            "source": "protocol_http_client",
        }
    except Exception as exc:
        sys.stderr.write("[bridge] 流量统计读取失败: %s\n" % exc)

    # 拿不到 access_token 时必须带上 error —— 不带的话调用方只会打出
    # "失败: None / 未知错误"，查起来毫无线索（实测吃过这个亏）。
    _err = "" if got_at else (
        "注册未拿到 access_token"
        + ("（2FA 也没拿到）" if not got_2fa else "")
        + ("（cookie 也没拿到）" if not got_cookie else "")
        + "；registered 表里只有部分凭证，多半是卡在等验证码/绑定 2FA"
    )
    _emit({"ok": got_at, "partial": not (got_at and got_2fa and got_cookie),
           "run_id": run_id, "result": d, "network_traffic": traffic, "error": _err,
           "have": {"access_token": got_at, "totp_secret": got_2fa, "cookie_header": got_cookie}})
    return 0 if got_at else 1


def main() -> int:
    try:
        job = json.loads(sys.stdin.read() or "{}")
    except Exception as exc:
        _emit({"ok": False, "error": f"job JSON 解析失败: {exc}"})
        return 2
    mode = str(job.get("mode") or "register").strip().lower()
    if mode == "check":
        return _check(job)
    return _register(job)


if __name__ == "__main__":
    raise SystemExit(main())
