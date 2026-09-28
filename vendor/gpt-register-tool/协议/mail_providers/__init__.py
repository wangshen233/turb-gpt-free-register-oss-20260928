"""邮箱 Provider 包 —— 加新邮箱只改这个目录。

用法（registrar / app / auto_loop 的唯一入口）：

    from mail_providers import create_mail_provider, list_providers

    mail = create_mail_provider("outlook", settings, account)
    mail = create_mail_provider("cf_temp", settings)

加一种新邮箱：

    1. 新建 mail_providers/xxx.py，继承 MailProvider，实现
       create_mailbox() / wait_for_otp() / from_config()
    2. 在本文件底部的「注册区」加一行 import

核心库（auth_flow / registrar / db / app / auto_loop）一行不动。
"""
from __future__ import annotations

from .base import (  # noqa: F401
    ConfigField,
    ImportValidationError,
    MailProvider,
    MailProviderError,
    create_mail_provider,
    extract_otp,
    get_provider_class,
    list_pooled_providers,
    list_providers,
    parse_import_line,
    parse_import_text,
    register,
    validate_email,
)

# ════════════════════════════════════════════════════════════
#  注册区 —— 加 provider 在这里加一行 import 即可
#  （import 时会触发模块内的 @register 装饰器完成注册）
# ════════════════════════════════════════════════════════════

from . import outlook        # noqa: F401,E402  kind="outlook"
from . import cf_temp        # noqa: F401,E402  kind="cf_temp"
from . import icloud_relay   # noqa: F401,E402  kind="icloud_relay"

__all__ = [
    "MailProvider",
    "MailProviderError",
    "ImportValidationError",
    "ConfigField",
    "register",
    "get_provider_class",
    "create_mail_provider",
    "list_providers",
    "list_pooled_providers",
    "parse_import_line",
    "parse_import_text",
    "validate_email",
    "extract_otp",
]
