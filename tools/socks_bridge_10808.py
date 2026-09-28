# -*- coding: utf-8 -*-
"""把本机 SOCKS 入口接到海外住宅代理。

大陆 IP 直连部分住宅网关（例如 gate2.ipweb.cc:7778）会在 SOCKS 握手后立刻断开。
本桥监听 127.0.0.1:11080，先走本机 xray/clash 的 10808，再轮询上游 SOCKS5。

用法：
    1. 把上游代理写成 tools/upstream_proxies.txt，每行 host:port:user:pass 或 socks5h://user:pass@host:port
    2. 本机 10808 已开启
    3. python tools/socks_bridge_10808.py
    4. PROXY_POOL=socks5h://127.0.0.1:11080
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import random
import socket
import struct
import threading
import time
from pathlib import Path
from urllib.parse import urlparse, unquote

try:
    import socks
except ImportError as exc:  # pragma: no cover
    raise SystemExit("缺少 PySocks，请先 pip install PySocks") from exc

ROOT = Path(__file__).resolve().parent.parent
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 11080
# 下一跳：本机 xray/clash 的 SOCKS5。服务器上没有本地代理客户端时用
# `--hop=direct`（或 BRIDGE_HOP=direct）直接拨上游网关。
DEFAULT_HOP: tuple[str, int] = ("127.0.0.1", 10808)
UPSTREAM: tuple[str, int] | None = DEFAULT_HOP
UPSTREAM_FILE = ROOT / "tools" / "upstream_proxies.txt"

# ---------------------------------------------------------------------------
# 直连 SESSION 模式（123Proxy 等可直连网关）
#
# 这类网关默认「每次请求轮换出口」，一次注册会跨十几个国家的 IP，风控直接判死。
# 官方支持的粘性写法是：
#
#     用户名-sess_<12位ID>_<分钟>+<小写国家码>
#
# 例如 2714241991-sess_a8F3kP9xQ2mL_30+vn 会在 30 分钟内固定同一个越南住宅出口。
# 这里把客户端在代理 URL 里带的 session key 哈希成 12 位 ID，于是同一个账号的
# 所有请求（chatgpt.com / auth.openai.com / sentinel.openai.com）自动落到同一个出口。
# ---------------------------------------------------------------------------
DIRECT_PROXY: tuple[str, int] | None = None
SESSION_BASE_USER = ""
SESSION_PASSWORD = ""
SESSION_MINUTES = 30
SESSION_COUNTRY = "vn"
SESSION_ATTEMPTS = 3

# 多账号池模式（薅羊毛型供应商：一个账号只有几 MB 流量）。
# 用户文件是 JSON 数组，每项形如：
#   {"session_key": "u1", "host": "...", "port": 9120,
#    "sticky_user": "u1-session-<id>-sesstime-30", "password": "..."}
# 未提供 sticky_user 时用 username 原样。
SESSION_USER_FILE = ""
_SESSION_USERS: list[dict] = []


def _is_rotate_key(session_key: str) -> bool:
    """rotate* 语义：这个 session key **不粘性**，每次连接随机换出口。

    用途：优惠检测 / 查套餐这类「同一个 key 在几分钟内打几十次」的场景。
    默认的粘性哈希会让所有检测都从**同一个住宅 IP** 出去 —— 既把风险集中到一个 IP，
    也让判定结果被那一个 IP 绑死（2026-09-19 实测：45 次查优惠全走 pool[14] 一个 IP，
    0 元率从 88% 掉到 19%；换个出口重查，同一批号立刻又出 0 元）。
    注册流程不能用它（注册要全程同一出口），只有检测用。
    """
    return str(session_key or "").strip().lower().startswith("rotate")


def session_sid(session_key: str, attempt: int = 0) -> str:
    """把 session key 稳定映射成 12 位 SESSION ID（小写字母数字）。"""
    raw = f"{session_key}#{attempt}" if attempt else str(session_key)
    digest = hashlib.sha1(raw.encode("utf-8", "replace")).digest()
    return base64.b32encode(digest).decode("ascii").rstrip("=").lower()[:12]


def load_session_users(path_str: str) -> list[dict]:
    """读取多账号用户池。每项至少要有 host / port / user / password。"""
    import json as _json

    path = Path(path_str)
    if not path.exists():
        raise SystemExit("未找到用户池文件: %s" % path)
    raw = _json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or not raw:
        raise SystemExit("用户池文件必须是至少含一项的 JSON 数组")
    out: list[dict] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or "").strip()
        port = int(item.get("port") or 0)
        user = str(item.get("username") or item.get("user") or "").strip()
        password = str(item.get("password") or item.get("pass") or "")
        if not host or not port or not user:
            raise SystemExit("用户池第 %d 项缺少 host/port/username" % idx)
        sticky = str(item.get("sticky_user") or user).strip()
        out.append({
            "label": str(item.get("session_key") or user),
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "sticky_user": sticky,
        })
    if not out:
        raise SystemExit("用户池文件解析后为空")
    return out


def pick_session_user(session_key: str) -> dict:
    """把 session key 稳定映射到池子里某一个账号。

    同一个账号的所有请求固定用同一套凭据，注册中途不会换号；
    不同账号分散到不同上游账号，这样每个小流量账号只用掉自己那一份。
    """
    if not _SESSION_USERS:
        raise SystemExit("用户池为空")
    digest = hashlib.sha1(str(session_key).encode("utf-8", "replace")).digest()
    return _SESSION_USERS[int.from_bytes(digest[:4], "big") % len(_SESSION_USERS)]


def render_sticky_user(template: str, session_key: str, attempt: int = 0) -> str:
    """把粘性用户名模板里的占位符换成真值。

    cloudbypass 的用户名语法（下划线分隔的后缀）：
        用户名[_国家][_会话名-时长]
    实测有效：11181551-res_VN_sabcdef123456-30m
    这里支持 {SID} -> 12 位会话 ID，{MIN} -> 粘性分钟数。
    """
    text = str(template or "")
    if "{SID}" in text:
        text = text.replace("{SID}", session_sid(session_key, attempt))
    if "{MIN}" in text:
        text = text.replace("{MIN}", str(int(SESSION_MINUTES)))
    return text


def session_username(session_key: str, attempt: int = 0) -> str:
    """拼出粘性 SESSION 用户名。"""
    return (
        f"{SESSION_BASE_USER}-sess_{session_sid(session_key, attempt)}"
        f"_{int(SESSION_MINUTES)}+{str(SESSION_COUNTRY).strip().lower()}"
    )


_direct_ip_cache: dict[str, tuple[str, float]] = {}
_direct_ip_lock = threading.Lock()
DIRECT_IP_TTL = 300.0


def invalidate_direct_ip() -> None:
    """标记网关 IP 缓存失效，下次重新探测。"""
    with _direct_ip_lock:
        _direct_ip_cache.clear()


def resolve_direct_proxy(timeout: float = 4.0) -> tuple[str, int]:
    """挑一个真正能连上的网关 IP。

    网关域名有多条 A 记录，其中一部分是死的（实测 3 条里 1 条超时）。
    PySocks / 普通 socket.connect 只会用 getaddrinfo 的第一个结果，
    正好撞上死 IP 时整条链路 10 秒超时 —— 桥接卡死的根因就在这里。
    这里逐个 TCP 探测并缓存可用的那条。
    """
    if DIRECT_PROXY is None:
        return UPSTREAM or ("127.0.0.1", 10808)
    host, port = DIRECT_PROXY
    now = time.time()
    with _direct_ip_lock:
        cached = _direct_ip_cache.get(host)
        if cached and cached[1] > now:
            return cached[0], port

    try:
        addrs = [
            item[4][0]
            for item in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        ]
    except Exception:
        addrs = []
    ordered: list[str] = []
    if cached:
        ordered.append(cached[0])
    for addr in addrs:
        if addr not in ordered:
            ordered.append(addr)
    if not ordered:
        return host, port

    for ip in ordered:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(timeout)
        try:
            probe.connect((ip, port))
        except Exception:
            continue
        finally:
            probe.close()
        with _direct_ip_lock:
            _direct_ip_cache[host] = (ip, time.time() + DIRECT_IP_TTL)
        print(f"direct_gateway_ip {host} -> {ip}", flush=True)
        return ip, port
    print(f"direct_gateway_ip {host} -> none reachable of {ordered}", flush=True)
    return ordered[0], port


def _normalize_proxy_line(raw: str) -> tuple[str, int, str, str] | None:
    text = str(raw or "").strip()
    if not text or text.startswith("#"):
        return None
    for junk in ("\u00b7", "\u2022", "\u30fb", "\uff0e"):
        text = text.replace(junk, ".")
    if "://" not in text and text.count(":") >= 3:
        host, port, user, password = text.split(":", 3)
        return host, int(port), user, password
    if "://" not in text:
        text = "socks5h://" + text
    parsed = urlparse(text)
    if not parsed.hostname or not parsed.port:
        return None
    return parsed.hostname, int(parsed.port), unquote(parsed.username or ""), unquote(parsed.password or "")


def load_upstreams(path: Path) -> list[tuple[str, int, str, str]]:
    if not path.exists():
        raise SystemExit(f"未找到上游代理文件: {path}")
    out: list[tuple[str, int, str, str]] = []
    seen: set[tuple[str, int, str, str]] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        item = _normalize_proxy_line(raw)
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    if not out:
        raise SystemExit(f"{path} 里没有可用的上游代理")
    return out


def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def parse_hop(value: str) -> tuple[str, int] | None:
    """--hop 的取值：`host:port` 走下一跳 SOCKS5，`direct` 直接拨上游。"""
    text = (value or "").strip()
    if not text:
        return DEFAULT_HOP
    if text.lower() in ("direct", "-", "none", "off"):
        return None
    host, _, port_s = text.rpartition(":")
    if not host or not port_s.isdigit():
        raise SystemExit("--hop 格式应为 host:port 或 direct")
    return (host, int(port_s))


def open_to(host: str, port: int, timeout: int = 15):
    """建一条到 host:port 的 TCP 连接；配了下一跳就经 SOCKS5 隧道（远端 DNS）。"""
    if UPSTREAM is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return sock
    sock = socks.socksocket()
    sock.set_proxy(socks.SOCKS5, UPSTREAM[0], UPSTREAM[1], rdns=True)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def socks5_connect_via_local(host: str, port: int, user: str, password: str, timeout: int = 15):
    """连到上游 SOCKS5 并完成 RFC1929 认证，返回已握手的 socket。

    非 SESSION 模式：先经本机 10808 的 SOCKS5 隧道跳到 host:port（10808 不需要
    认证），再手工对真正的上游做 SOCKS5 用户名/密码认证。

    SESSION 模式：host:port 就是网关本身，直接建 TCP 连接，然后同样手工认证 ——
    这里不能用 PySocks，因为 set_proxy 会把网关当成代理去 CONNECT，等于套了两层。
    """
    if DIRECT_PROXY is not None:
        gw_host, gw_port = resolve_direct_proxy()
        try:
            socket.getaddrinfo(gw_host, gw_port, socket.AF_INET, socket.SOCK_STREAM)
            local_dns_ok = True
        except OSError:
            # 网关域名本地解析不了（实测 Errno 11004：本地 DNS 拿不到网关域名），
            # 这种情况必须经下一跳做远端 DNS + TCP 跳板。
            local_dns_ok = False
        if local_dns_ok:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((gw_host, gw_port))
        else:
            sock = open_to(gw_host, gw_port, timeout)
    else:
        sock = open_to(host, port, timeout)
    sock.sendall(b"\x05\x01\x02")
    greet = recv_exact(sock, 2)
    if greet[0] != 5 or greet[1] != 2:
        raise ConnectionError("upstream greet " + greet.hex())
    user_b = user.encode()
    pass_b = password.encode()
    sock.sendall(b"\x01" + bytes([len(user_b)]) + user_b + bytes([len(pass_b)]) + pass_b)
    auth = recv_exact(sock, 2)
    if auth[1] != 0:
        raise ConnectionError("upstream auth fail " + str(auth[1]))
    return sock


def pipe(src, dst) -> None:
    try:
        while True:
            data = src.recv(16384)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    try:
        src.shutdown(socket.SHUT_RD)
    except Exception:
        pass
    try:
        dst.shutdown(socket.SHUT_WR)
    except Exception:
        pass


class Bridge:
    """轮询上游；单个上游握手/连接失败时自动切下一条（短期冷却）。

    之前一条坏代理会让整次请求以 curl(97) cannot complete SOCKS5 connection 失败，
    注册日志里表现为随机网络错误。现在坏上游只影响它自己那一次尝试。
    """

    # 失败后的冷却秒数：这段时间内不再优先选它
    BAD_COOLDOWN = 60
    MAX_ATTEMPTS = 6

    def __init__(self, upstreams: list[tuple[str, int, str, str]]):
        self.upstreams = upstreams
        self.seq = 0
        self.lock = threading.Lock()
        self.bad_until: dict[int, float] = {}
        self.stat_ok = 0
        self.stat_bad = 0
        # 会话粘性：同一个 SOCKS5 账号（客户端在代理 URL 里带的 session key）
        # 必须固定落到同一条上游，否则一次注册的 chatgpt.com / auth.openai.com /
        # sentinel.openai.com 会各走一个出口 IP，风控一眼看出不是同一个"人"。
        self.sticky_seen: dict[str, int] = {}
        self.session_totals: dict[str, dict] = {}

    def sticky_index(self, key: str) -> int:
        """把 session key 稳定映射到某条上游（哈希取模，无状态、可复现）。"""
        digest = hashlib.sha1(str(key).encode("utf-8", "replace")).digest()
        return int.from_bytes(digest[:4], "big") % max(1, len(self.upstreams))

    def note_session(self, key: str, idx: int, dest: str) -> None:
        """同一 session 第一次出现时打一行日志，之后只累计连接数。"""
        stat = self.session_totals.get(key)
        if stat is None:
            stat = {"idx": idx, "conns": 0, "dests": set()}
            self.session_totals[key] = stat
            self.sticky_seen[key] = idx
            print(
                f"sticky_new key={key} upstream={idx} dest={dest}",
                flush=True,
            )
        stat["conns"] += 1
        stat["dests"].add(dest)
        if stat["conns"] in (2, 5, 10, 25, 50, 100):
            print(
                f"sticky_reuse key={key} upstream={stat['idx']} conns={stat['conns']} dests={len(stat['dests'])}",
                flush=True,
            )

    def pick(self) -> tuple[str, int, str, str]:
        with self.lock:
            idx = self.seq
            self.seq += 1
        return self.upstreams[idx % len(self.upstreams)]

    def candidates(self, session_key: str = "") -> list[tuple[int, tuple[str, int, str, str]]]:
        """返回最多 MAX_ATTEMPTS 条候选（跳过冷却中的）。

        带 session_key 时从该会话固定的上游开始（第一条失败才顺延到别的上游），
        不带 session_key 时保持原来的全局轮询行为。
        """
        if SESSION_USER_FILE:
            # 多账号池模式：同一个 session 固定用一个上游账号，失败才顺延到池子里的下一个。
            total = len(_SESSION_USERS)
            if session_key:
                digest = hashlib.sha1(str(session_key).encode("utf-8", "replace")).digest()
                start = int.from_bytes(digest[:4], "big") % max(1, total)
            else:
                with self.lock:
                    start = self.seq
                    self.seq += 1
            # 池子模式必须也看冷却标记：住宅免费额度用光后，网关会一直回
            # auth fail 255，账号再也不会恢复。原实现每次都按顺序从头取，
            # 于是每次请求都要先撞几条死号，表现为
            #     ProxyError: curl: (97) cannot complete SOCKS5 connection
            # 这里把「冷却中 / 已知失败过」的账号排到后面，并把尝试上限放大，
            # 让一次请求能真正走到活号上。
            now = time.time()
            fresh: list[int] = []
            cooled: list[int] = []
            for step in range(total):
                idx = (start + step) % total
                (cooled if self.bad_until.get(idx, 0.0) > now else fresh).append(idx)
            # 失败次数少的优先（没失败过的最优先）
            pool_ok = getattr(self, "pool_fail", None)
            if pool_ok is None:
                pool_ok = self.pool_fail = {}
            fresh.sort(key=lambda i: pool_ok.get(i, 0))
            order = (fresh + cooled)[: max(self.MAX_ATTEMPTS, 12)]
            pooled: list[tuple[int, tuple[str, int, str, str]]] = []
            for step, idx in enumerate(order):
                item = _SESSION_USERS[idx]
                pooled.append((
                    idx,   # 用真实池位当 key，mark_bad / mark_ok 才能对上号
                    (item["host"], item["port"],
                     render_sticky_user(item["sticky_user"], session_key, step),
                     item["password"]),
                ))
            return pooled
        if DIRECT_PROXY is not None:
            # SESSION 模式：不是从列表里挑，而是按 session key 现算粘性用户名。
            # 同一个 sid 命中同一个住宅出口；sid 不同即不同出口（用于故障重试）。
            keys = [session_key] if session_key else ["anonymous"]
            gw_host, gw_port = resolve_direct_proxy()
            out: list[tuple[int, tuple[str, int, str, str]]] = []
            for attempt in range(self.MAX_ATTEMPTS):
                key = keys[0] if attempt == 0 else f"{keys[0]}#retry{attempt}"
                out.append((attempt, (gw_host, gw_port, session_username(key, 0), SESSION_PASSWORD)))
            return out
        total = len(self.upstreams)
        if session_key and _is_rotate_key(session_key):
            start = random.randrange(max(1, total))   # 不粘性：每次连接随机换出口
        elif session_key:
            start = self.sticky_index(session_key)
        else:
            with self.lock:
                start = self.seq
                self.seq += 1
        if (os.environ.get("BRIDGE_STRICT_STICKY", "") or "").strip().lower() in ("1", "true", "yes") \
                and session_key and not _is_rotate_key(session_key):
            # 严格粘性：只给粘性那一条出口，**不顺延到别的上游**。
            # 注册/支付这类「全程必须同一个出口 IP」的流程必须开它 ——
            # 中途换 IP 会让 Stripe 直接掐连接（表现为 api.stripe.com 反复 curl (56)）。
            return [(start, self.upstreams[start])]
        now = time.time()
        fresh: list[tuple[int, tuple[str, int, str, str]]] = []
        cooled: list[tuple[int, tuple[str, int, str, str]]] = []
        for step in range(total):
            idx = (start + step) % total
            item = (idx, self.upstreams[idx])
            if self.bad_until.get(idx, 0.0) > now:
                cooled.append(item)
            else:
                fresh.append(item)
            if len(fresh) >= self.MAX_ATTEMPTS:
                break
        if not fresh:
            fresh = cooled[: self.MAX_ATTEMPTS]
        return fresh

    def mark_bad(self, idx: int) -> None:
        # 池子模式下 idx 是真实池位；连续失败两次以上就按「账号已跑干」处理：
        # 住宅免费额度用光后网关永久回 auth fail 255，给它一个很长的冷却，
        # 免得每次请求都先去撞它。
        long_dead = False
        if SESSION_USER_FILE:
            fails = self.pool_fail.get(idx, 0) + 1 if hasattr(self, "pool_fail") else 1
            if not hasattr(self, "pool_fail"):
                self.pool_fail = {}
            self.pool_fail[idx] = fails
            long_dead = fails >= 2
        with self.lock:
            cooldown = 1800.0 if long_dead else self.BAD_COOLDOWN
            self.bad_until[idx] = time.time() + cooldown
            self.stat_bad += 1
        if DIRECT_PROXY is not None:
            # 网关 IP 可能刚被打死，下次重新探测。
            invalidate_direct_ip()

    def mark_ok(self, idx: int) -> None:
        if SESSION_USER_FILE and hasattr(self, "pool_fail"):
            self.pool_fail.pop(idx, None)
        with self.lock:
            self.bad_until.pop(idx, None)
            self.stat_ok += 1

    def handle(self, client) -> None:
        upstream = None
        session_key = ""
        try:
            client.settimeout(20)
            ver_n = recv_exact(client, 2)
            if ver_n[0] != 5:
                client.close()
                return
            methods = recv_exact(client, ver_n[1])
            # 客户端在代理 URL 里带 user:pass 时走 RFC1929，把用户名当作会话粘性 key；
            # 没带就退回无认证老行为（全局轮询）。
            if 2 in methods:
                client.sendall(b"\x05\x02")
                auth_hdr = recv_exact(client, 2)
                ulen = auth_hdr[1]
                uname = recv_exact(client, ulen) if ulen else b""
                plen = recv_exact(client, 1)[0]
                if plen:
                    recv_exact(client, plen)
                session_key = uname.decode("utf-8", "replace").strip()
                client.sendall(b"\x01\x00")
            else:
                client.sendall(b"\x05\x00")
            hdr = recv_exact(client, 4)
            if hdr[0] != 5 or hdr[1] != 1:
                client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                client.close()
                return
            atyp = hdr[3]
            if atyp == 1:
                dest_host = socket.inet_ntoa(recv_exact(client, 4))
            elif atyp == 3:
                length = recv_exact(client, 1)[0]
                dest_host = recv_exact(client, length).decode("ascii", "replace")
            elif atyp == 4:
                dest_host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
            else:
                client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
                client.close()
                return
            dest_port = struct.unpack("!H", recv_exact(client, 2))[0]
            req = b"\x05\x01\x00"
            if atyp == 1:
                req += b"\x01" + socket.inet_aton(dest_host)
            elif atyp == 4:
                req += b"\x04" + socket.inet_pton(socket.AF_INET6, dest_host)
            else:
                host_b = dest_host.encode()
                req += b"\x03" + bytes([len(host_b)]) + host_b
            req += struct.pack("!H", dest_port)

            last_exc: Exception | None = None
            if session_key:
                self.note_session(
                    session_key,
                    self.sticky_index(session_key),
                    f"{dest_host}:{dest_port}",
                )
            for idx, (host, port, user, password) in self.candidates(session_key):
                try:
                    upstream = socks5_connect_via_local(host, port, user, password)
                    upstream.sendall(req)
                    resp = recv_exact(upstream, 4)
                    if resp[3] == 1:
                        resp += recv_exact(upstream, 6)
                    elif resp[3] == 3:
                        length = recv_exact(upstream, 1)
                        resp += length + recv_exact(upstream, length[0] + 2)
                    elif resp[3] == 4:
                        resp += recv_exact(upstream, 18)
                    if resp[1] != 0:
                        raise ConnectionError(f"upstream connect rc={resp[1]}")
                    self.mark_ok(idx)
                    client.sendall(resp)
                    break
                except Exception as exc:
                    last_exc = exc
                    self.mark_bad(idx)
                    print(
                        f"upstream_retry user={user} {type(exc).__name__}: {str(exc)[:120]}",
                        flush=True,
                    )
                    try:
                        if upstream is not None:
                            upstream.close()
                    except Exception:
                        pass
                    upstream = None
            else:
                print(f"upstream_exhausted dest={dest_host}:{dest_port} last={last_exc}", flush=True)
                client.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)
                return
            upstream.settimeout(None)
            client.settimeout(None)
            t1 = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
            t2 = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception as exc:
            try:
                client.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)
            except Exception:
                pass
            print("handle_fail", type(exc).__name__, str(exc)[:160], flush=True)
        finally:
            try:
                client.close()
            except Exception:
                pass
            if upstream is not None:
                try:
                    upstream.close()
                except Exception:
                    pass

    def serve(self, host: str, port: int) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(64)
        hop = "direct" if UPSTREAM is None else f"{UPSTREAM[0]}:{UPSTREAM[1]}"
        print(f"BRIDGE_LISTEN socks5://{host}:{port} hop={hop} -> {len(self.upstreams)} upstreams", flush=True)
        while True:
            client, _addr = srv.accept()
            threading.Thread(target=self.handle, args=(client,), daemon=True).start()


def main() -> None:
    global UPSTREAM, DIRECT_PROXY, SESSION_BASE_USER, SESSION_PASSWORD, SESSION_MINUTES, SESSION_COUNTRY, SESSION_USER_FILE, _SESSION_USERS
    parser = argparse.ArgumentParser(description="本机 10808 跳板到海外 SOCKS5")
    parser.add_argument("--listen", default=os.environ.get("BRIDGE_LISTEN", f"{LISTEN_HOST}:{LISTEN_PORT}"))
    parser.add_argument(
        "--hop",
        default=os.environ.get("BRIDGE_HOP", ""),
        help="下一跳 SOCKS5（默认 127.0.0.1:10808）；服务器上没有本地代理客户端时传 direct 直连上游",
    )
    parser.add_argument("--file", default=str(UPSTREAM_FILE), help="上游代理列表，默认 tools/upstream_proxies.txt")
    parser.add_argument(
        "--sess-proxy",
        default="",
        help="直连 SESSION 网关 host:port:user:pass（例如 123Proxy）；给了就忽略 --file",
    )
    parser.add_argument("--sess-country", default="vn", help="SESSION 国家码，小写，默认 vn")
    parser.add_argument("--sess-minutes", type=int, default=30, help="SESSION 粘性时长（分钟），默认 30")
    parser.add_argument(
        "--sess-user-file",
        default="",
        help="多账号用户池 JSON（每项 host/port/username/password[/sticky_user/session_key]）",
    )
    args = parser.parse_args()
    host, port_s = args.listen.rsplit(":", 1)
    UPSTREAM = parse_hop(args.hop)

    if args.sess_user_file.strip():
        SESSION_USER_FILE = args.sess_user_file.strip()
        _SESSION_USERS = load_session_users(SESSION_USER_FILE)
        upstreams = []
        print(
            "USER_POOL mode users=%d file=%s" % (len(_SESSION_USERS), SESSION_USER_FILE),
            flush=True,
        )
    elif args.sess_proxy.strip():
        parsed = _normalize_proxy_line(args.sess_proxy)
        if not parsed:
            raise SystemExit(f"--sess-proxy 格式无效: {args.sess_proxy}")
        shost, sport, suser, spass = parsed
        DIRECT_PROXY = (shost, sport)
        SESSION_BASE_USER = suser
        SESSION_PASSWORD = spass
        SESSION_MINUTES = max(1, min(120, int(args.sess_minutes)))
        SESSION_COUNTRY = str(args.sess_country).strip().lower()
        upstreams: list[tuple[str, int, str, str]] = []
        print(
            f"SESSION_MODE gateway={shost}:{sport} country={SESSION_COUNTRY} minutes={SESSION_MINUTES}",
            flush=True,
        )
    else:
        upstreams = load_upstreams(Path(args.file))
        print("upstream_count", len(upstreams), flush=True)

    Bridge(upstreams).serve(host, int(port_s))


if __name__ == "__main__":
    main()
