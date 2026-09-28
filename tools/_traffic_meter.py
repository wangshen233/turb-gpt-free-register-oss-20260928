# -*- coding: utf-8 -*-
"""按字节计量 SOCKS5 转发代理（用于独立核对一次注册的真实流量）。

链路：客户端 -> 本代理(--listen) -> 上游链(--chain, SOCKS5) -> 目标
对两个方向的原始字节分别计数，输出 json 供脚本读取。
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import threading
import time

STATS = {"up": 0, "down": 0, "conns": 0}
LOCK = threading.Lock()
CHAIN = ("127.0.0.1", 11086)
# 客户端没带用户名时统一用的会话名。给一个固定值，保证一次注册全程落在
# 同一个住宅账号 + 同一个粘性出口 IP 上（不带的话桥接会按连接轮询换账号）。
FALLBACK_USER = ""


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def add(up=0, down=0):
    with LOCK:
        STATS["up"] += up
        STATS["down"] += down


def pipe(src, dst, direction, sock_mark):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            if direction == "up":
                add(up=len(data))
            else:
                add(down=len(data))
            dst.sendall(data)
    except Exception:
        pass
    for s in (src, dst):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass


def chain_connect(host, port, user=""):
    """连到 --chain 指定的 SOCKS5 上游。

    如果客户端在代理 URL 里带了用户名（注册机注入的 oai-<hash> 会话名），
    这里必须把它透传给上游 —— 否则每一条连接都会被上游当成新会话，
    一个注册流程的多个请求会落到不同的住宅账号上，出口 IP 中途乱跳。
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect(CHAIN)
    if user:
        s.sendall(b"\x05\x01\x02")
        greet = recv_exact(s, 2)
        if greet[1] != 2:
            raise ConnectionError("chain no-auth-method fail")
        ub = user.encode()
        s.sendall(b"\x01" + bytes([len(ub)]) + ub + b"\x01x")
        auth = recv_exact(s, 2)
        if auth[1] != 0:
            raise ConnectionError("chain auth fail %d" % auth[1])
    else:
        s.sendall(b"\x05\x01\x00")
        greet = recv_exact(s, 2)
        if greet[1] != 0:
            raise ConnectionError("chain no-auth fail")
    hb = host.encode()
    req = b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", port)
    s.sendall(req)
    resp = recv_exact(s, 4)
    if resp[1] != 0:
        raise ConnectionError("chain connect rc=%d" % resp[1])
    atyp = resp[3]
    if atyp == 1: recv_exact(s, 6)
    elif atyp == 3: recv_exact(s, recv_exact(s, 1)[0] + 2)
    elif atyp == 4: recv_exact(s, 18)
    return s


def handle(client):
    upstream = None
    session_user = ""
    try:
        client.settimeout(25)
        ver_n = recv_exact(client, 2)
        methods = recv_exact(client, ver_n[1])
        if 2 in methods:
            client.sendall(b"\x05\x02")
            uh = recv_exact(client, 2)
            session_user = recv_exact(client, uh[1]).decode("utf-8", "replace") if uh[1] else ""
            pl = recv_exact(client, 1)[0]
            if pl: recv_exact(client, pl)
            client.sendall(b"\x01\x00")
        else:
            client.sendall(b"\x05\x00")
        hdr = recv_exact(client, 4)
        atyp = hdr[3]
        if atyp == 1:
            host = socket.inet_ntoa(recv_exact(client, 4))
        elif atyp == 3:
            host = recv_exact(client, recv_exact(client, 1)[0]).decode("ascii", "replace")
        else:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        port = struct.unpack("!H", recv_exact(client, 2))[0]
        upstream = chain_connect(host, port, session_user or FALLBACK_USER)
        with LOCK:
            STATS["conns"] += 1
        client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        client.settimeout(None)
        upstream.settimeout(None)
        t1 = threading.Thread(target=pipe, args=(client, upstream, "up", 0), daemon=True)
        t2 = threading.Thread(target=pipe, args=(upstream, client, "down", 0), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
    except Exception:
        pass
    finally:
        for s in (client, upstream):
            try:
                if s: s.close()
            except Exception:
                pass


def main():
    global CHAIN, FALLBACK_USER
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:11099")
    ap.add_argument("--chain", default="127.0.0.1:11086")
    ap.add_argument("--session-user", default="", help="客户端没带用户名时统一使用的会话名")
    a = ap.parse_args()
    CHAIN = (a.chain.split(":")[0], int(a.chain.split(":")[1]))
    FALLBACK_USER = str(a.session_user or "").strip()
    host, port = a.listen.split(":")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, int(port)))
    srv.listen(64)
    print("METER_LISTEN %s chain=%s session_user=%s" % (a.listen, a.chain, FALLBACK_USER or "-"), flush=True)
    def reporter():
        while True:
            time.sleep(5)
            with LOCK:
                snap = dict(STATS)
            print("METER up=%d down=%d total=%d conns=%d" % (snap["up"], snap["down"], snap["up"]+snap["down"], snap["conns"]), flush=True)
            try:
                import os as _os
                with open(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "_traffic_meter.json"), "w") as fh:
                    json.dump({"up": snap["up"], "down": snap["down"],
                               "total": snap["up"] + snap["down"], "conns": snap["conns"]}, fh)
            except Exception:
                pass
    threading.Thread(target=reporter, daemon=True).start()
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()