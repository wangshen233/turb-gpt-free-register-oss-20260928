# -*- coding: utf-8 -*-
"""清理测试开出来的 roxy 环境（真报错，不吞）。"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from core.roxybrowser_client import RoxyBrowserClient

c = RoxyBrowserClient()
ok = fail = 0
for pid in sys.argv[1:]:
    for path in ('/browser/close', '/browser/delete'):
        try:
            r = c.request('POST', path, json_body={'workspaceId': 90143, 'dirId': pid})
            ok += 1
        except Exception as e:
            msg = str(e)
            if 'not open' in msg or 'invalid dirId' in msg:
                ok += 1   # 本来就已经关掉/删掉了
            else:
                fail += 1
                print('  %s %s -> %s' % (path, pid[:12], msg[:80]))
print('清理: 成功/无需处理 %d，失败 %d' % (ok, fail))
