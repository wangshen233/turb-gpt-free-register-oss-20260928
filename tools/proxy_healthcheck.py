# -*- coding: utf-8 -*-
"""按国家健康检查上游住宅代理：区分「可用 / Cloudflare 403 拦截 / 完全不通」。

背景：住宅池里有一部分 IP 被 Cloudflare 拦（chatgpt.com 返回 403 HTML），
桥是轮询取的，所以查优惠/查活会随机大量 403。把干净 IP 挑出来单独成表，
桥只挂干净表即可。

判定依据（匿名请求，无需 token）：
    401 + JSON  -> Cloudflare 放行（只是没带 token），= 干净
    200 + JSON  -> 干净
    403 + HTML  -> 被拦截
    连接失败    -> 不可用

用法：
    python tools/proxy_healthcheck.py --file tools/upstream_proxies_vn.txt
    python tools/proxy_healthcheck.py --file tools/upstream_proxies_jp.txt --threads 20
输出：
    <file 同目录>/<stem>_clean.txt   （注释头 + 干净条目，顺序与输入一致）
"""
from __future__ import annotations

import argparse
import socket
import ssl
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from socks_bridge_10808 import recv_exact, socks5_connect_via_local  # noqa: E402

PROBE_HOST = "chatgpt.com"
PROBE_PATH = "/backend-api/accounts/check/v4-2023-04-27?timezone_offset_min=-"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
)


def load_upstreams(path: Path) -> list[tuple[str, str, int, str, str]]:
    rows: list[tuple[str, str, int, str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        host, port, user, password = text.split(":", 3)
        rows.append((text, host, int(port), user, password))
    return rows


def _open_tunnel(host: str, port: int, user: str, password: str, timeout: int = 12):
    sock = socks5_connect_via_local(host, port, user, password, timeout=timeout)
    host_b = PROBE_HOST.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", 443))
    resp = recv_exact(sock, 4)
    if resp[3] == 1:
        resp += recv_exact(sock, 6)
    elif resp[3] == 3:
        length = recv_exact(sock, 1)
        resp += length + recv_exact(sock, length[0] + 2)
    elif resp[3] == 4:
        resp += recv_exact(sock, 18)
    if resp[1] != 0:
        sock.close()
        raise ConnectionError(f"upstream connect rc={resp[1]}")
    ctx = ssl.create_default_context()
    tls = ctx.wrap_socket(sock, server_hostname=PROBE_HOST)
    tls.settimeout(timeout)
    return tls


def probe(item: tuple[str, str, int, str, str]) -> tuple[str, str, str]:
    line, host, port, user, password = item
    tls = None
    started = time.time()
    try:
        tls = _open_tunnel(host, port, user, password)
        req = (
            f"GET {PROBE_PATH} HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\n"
            f"x-openai-target-path: {PROBE_PATH.split('?')[0]}\r\n"
            f"x-openai-target-route: {PROBE_PATH.split('?')[0]}\r\n"
            "Connection: close\r\n\r\n"
        )
        tls.sendall(req.encode())
        buf = b""
        while len(buf) < 65536:
            try:
                chunk = tls.recv(8192)
            except Exception:
                break
            if not chunk:
                break
            buf += chunk
        text = buf.decode("utf-8", "replace")
        head = text.split("\r\n", 1)[0]
        parts = head.split()
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        lower = text.lower()
        is_html = "<html" in lower or "<!doctype html" in lower
        if status in (200, 401):
            verdict = "clean"
        elif status == 403:
            verdict = "blocked"
        elif status == 0:
            verdict = "empty"
        else:
            verdict = f"http{status}"
        return line, verdict, f"{status} html={is_html} {time.time() - started:.1f}s"
    except Exception as exc:
        return line, "dead", f"{type(exc).__name__}: {str(exc)[:70]}"
    finally:
        if tls is not None:
            try:
                tls.close()
            except Exception:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="住宅代理 chatgpt.com 可用性健康检查")
    parser.add_argument("--file", required=True, help="上游代理列表，每行 host:port:user:pass")
    parser.add_argument("--threads", type=int, default=16, help="并发数，默认 16")
    parser.add_argument("--out", default="", help="干净列表输出路径，默认 <stem>_clean.txt")
    parser.add_argument("--quiet", action="store_true", help="只输出汇总")
    args = parser.parse_args()

    src = Path(args.file)
    if not src.is_absolute():
        src = ROOT / src
    rows = load_upstreams(src)
    if not rows:
        raise SystemExit(f"{src} 里没有可用的上游代理")

    print(f"source={src} upstreams={len(rows)} threads={args.threads}", flush=True)
    started = time.time()
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        results = list(pool.map(probe, rows))

    clean: list[str] = []
    tally: dict[str, int] = {}
    for line, verdict, detail in results:
        tally[verdict] = tally.get(verdict, 0) + 1
        if verdict == "clean":
            clean.append(line)
        elif not args.quiet:
            print(f"  [{verdict:>7}] {line.split(':')[2][:34]:<34} {detail}", flush=True)

    out_path = Path(args.out) if args.out else src.with_name(f"{src.stem}_clean.txt")
    if not out_path.is_absolute():
        out_path = ROOT / out_path
    header = (
        f"# clean upstreams for chatgpt.com (auto, {time.strftime('%Y-%m-%d %H:%M:%S')}) "
        f"clean/total={len(clean)}/{len(rows)}"
    )
    out_path.write_text("\n".join([header] + clean) + "\n", encoding="utf-8")

    print(flush=True)
    print(f"summary: {tally}  elapsed={time.time() - started:.1f}s", flush=True)
    print(f"clean={len(clean)}/{len(rows)} -> {out_path}", flush=True)


if __name__ == "__main__":
    main()
