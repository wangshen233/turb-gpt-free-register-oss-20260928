"""Cloudflare Worker 自建临时邮箱 —— 转发壳。

实现已迁至 mail_providers/cf_temp.py（继承统一的 MailProvider 基类）。
本文件仅保留原有的公开名字，让以下旧 import 路径继续可用：

    webui/app.py:379        from mail_cf import CFTempEmailProvider
    webui/registrar.py:166  from mail_cf import CFTempEmailProvider

新代码请直接用：

    from mail_providers import create_mail_provider
    mail = create_mail_provider("cf_temp", settings)
"""
from __future__ import annotations

from mail_providers.cf_temp import (  # noqa: F401
    CFTempEmailProvider,
    _extract_otp,
    _gen_local_part,
)

__all__ = ["CFTempEmailProvider"]


if __name__ == "__main__":
    # 命令行测试：python mail_cf.py <api_url> <admin_token> <domain>
    import logging
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if len(sys.argv) < 4:
        print("usage: python mail_cf.py <api_url> <admin_token> <domain>")
        sys.exit(2)
    p = CFTempEmailProvider(api_url=sys.argv[1], admin_token=sys.argv[2], domain=sys.argv[3])
    email = p.create_mailbox()
    print(f"创建邮箱: {email}")
    print("开始等待 OTP（120s）...")
    try:
        code = p.wait_for_otp(email, timeout=120)
        print(f"OTP: {code}")
    except TimeoutError as e:
        print(f"超时: {e}")
        sys.exit(1)
