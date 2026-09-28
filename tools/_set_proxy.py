# -*- coding: utf-8 -*-
"""安全改写 .env 里的 ROXY_UNLIMITED_PROXY（保留其它内容与编码）。"""
import re, sys
from pathlib import Path

p = Path(__file__).resolve().parent.parent / ".env"
text = p.read_text(encoding="utf-8")
new = sys.argv[1] if len(sys.argv) > 1 else ""
out, n = re.subn(r'^ROXY_UNLIMITED_PROXY="[^"]*"', 'ROXY_UNLIMITED_PROXY="%s"' % new, text, flags=re.M)
if n == 0:
    raise SystemExit("ROXY_UNLIMITED_PROXY line not found")
p.write_text(out, encoding="utf-8", newline="")
print("ROXY_UNLIMITED_PROXY ->", new)
