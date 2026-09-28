# -*- coding: utf-8 -*-
"""
mail.com 邮箱密码修改模块。

原依赖外部模块 mail_password_change（来自 chatgpt_mail_register_py 项目），
现自实现并集成进本项目，避免外部依赖。

实现来源：gpt-mail/register_mailcom.py 中的 change_mailcom_password()。
工作流：
    1. 用当前密码登录 mail.com lightmailer（建立 session cookies）
    2. 进入 account.mail.com 安全设置页（如未登录则用当前密码登录）
    3. 抽取 srttkn token + 表单 action
    4. POST 密码修改表单（currentPassword + newPassword + retypeNewPassword）
    5. 改密成功后回写 DB（email_pool.password）+ 内存缓存

注册前调用 maybe_change_mailcom_password_before_register(email) 即可：
    - 检测邮箱来源是否 mailcom
    - 读 config.EMAIL_SOURCE / MAILCOM_CHANGE_PASSWORD_BEFORE_REGISTER 开关
    - 改密、回写 DB 与缓存、返回新密码
"""

from __future__ import annotations

import logging
import re
import secrets
import string
from dataclasses import dataclass
from html import unescape
from urllib.parse import quote, urljoin

from bs4 import BeautifulSoup

from core.mailcom_client import (
    MailComError,
    MailComLightClient,
    _CONTEXT_CACHE,
    _http_session,
    _mailcom_proxy,
)

logger = logging.getLogger(__name__)

MAILCOM_ACCOUNT_BASE = "https://account.mail.com"
MAILCOM_ACCOUNT_PASSWORD_PATH = "/ciss/security/edit/passwordChange"
MAILCOM_DEFAULT_ACCEPT_LANGUAGE = "en-US,en;q=0.9"

PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*_+="
PASSWORD_SYMBOLS = "!@#$%^&*_+="


@dataclass(frozen=True)
class Account:
    """与外部 register_mailcom.Account 兼容的最小账号结构。"""

    username: str
    password: str


# ============================================================
# 密码生成
# ============================================================


def generate_mailcom_password(length: int = 12) -> str:
    """生成包含大小写字母、数字、符号的强密码（默认 12 位）。

    与 register_mailcom.generate_chatgpt_password 行为一致。
    """
    if length < 12:
        length = 12
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(PASSWORD_SYMBOLS),
    ]
    remaining = [
        secrets.choice(PASSWORD_ALPHABET) for _ in range(length - len(required))
    ]
    chars = required + remaining
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ============================================================
# HTML 解析辅助
# ============================================================


def _extract_form(
    html_text: str, form_id: str | None = None
) -> tuple[str, dict[str, str]]:
    """从 HTML 抽取指定表单的 action 与所有 input 名值对。"""
    soup = BeautifulSoup(html_text, "html.parser")
    form = soup.find("form", id=form_id) if form_id else soup.find("form")
    if not form:
        raise MailComError(f"mail.com 页面未找到表单: {form_id or '(first)'}")
    action = form.get("action") or ""
    payload: dict[str, str] = {}
    for input_node in form.find_all("input"):
        name = input_node.get("name")
        if name:
            payload[name] = input_node.get("value", "")
    return action, payload


def _extract_srttkn(*values: str) -> str:
    """从 URL / HTML 多个文本中抽取 srttkn token。"""
    haystack = "\n".join(values)
    patterns = [
        r"[?&]srttkn=([A-Za-z0-9._:-]+)",
        r'name=["\']srttkn["\'][^>]*value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'][^>]*name=["\']srttkn["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, haystack)
        if match:
            return unescape(match.group(1))
    raise MailComError("mail.com passwordChange 页面未找到 srttkn")


def _password_headers(
    referer: str,
    accept_language: str = MAILCOM_DEFAULT_ACCEPT_LANGUAGE,
) -> dict[str, str]:
    """构建访问 passwordChange 页面/提交表单的标准 headers。"""
    return {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": accept_language,
        "Cache-Control": "no-cache",
        "Origin": MAILCOM_ACCOUNT_BASE,
        "Pragma": "no-cache",
        "Referer": referer,
        "Sec-Fetch-Dest": "iframe",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }


# ============================================================
# 改密核心：登录 account.mail.com + 提交 passwordChange 表单
# ============================================================


def ensure_mailcom_account_session(
    client: MailComLightClient, current_password: str
) -> None:
    """确保 client.session 已登录 account.mail.com（与 lightmailer.mail.com 不同域）。

    若 GET account.mail.com/ 返回的页面已无 loginForm，则认为已登录，直接返回；
    否则用当前密码提交 loginForm 完成登录。
    """
    session = client.session
    page = session.get(
        f"{MAILCOM_ACCOUNT_BASE}/",
        headers={"Referer": "https://lightmailer.mail.com/settings"},
        timeout=30,
        allow_redirects=True,
    )
    page.raise_for_status()
    html = getattr(page, "text", "") or ""
    if (
        'id="loginForm"' not in html
        and 'name="loginForm"' not in html
        and "/ciss/login" not in getattr(page, "url", "")
    ):
        return

    action, payload = _extract_form(html, "loginForm")
    payload["username"] = client.username
    payload["password"] = current_password
    login = session.post(
        urljoin(getattr(page, "url", MAILCOM_ACCOUNT_BASE), action),
        data=payload,
        headers={
            "Origin": MAILCOM_ACCOUNT_BASE,
            "Referer": getattr(page, "url", MAILCOM_ACCOUNT_BASE),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=30,
        allow_redirects=True,
    )
    login.raise_for_status()
    login_text = getattr(login, "text", "") or ""
    if 'id="loginForm"' in login_text or "login-failed" in getattr(login, "url", ""):
        raise MailComError("mail.com account 登录失败，无法进入密码修改页")


def change_mailcom_password(
    client: MailComLightClient,
    current_password: str,
    new_password: str,
) -> None:
    """修改 mail.com 账号密码。

    Args:
        client: 已登录 lightmailer 的 MailComLightClient（需先 client.login()）
        current_password: 当前密码
        new_password: 新密码
    """
    session = client.session
    accept_language = str(
        getattr(client, "accept_language", "") or MAILCOM_DEFAULT_ACCEPT_LANGUAGE
    )
    ensure_mailcom_account_session(client, current_password)

    get_url = urljoin(MAILCOM_ACCOUNT_BASE, f"{MAILCOM_ACCOUNT_PASSWORD_PATH}?1")
    page = session.get(
        get_url,
        headers=_password_headers(MAILCOM_ACCOUNT_BASE, accept_language),
        timeout=30,
        allow_redirects=True,
    )
    page.raise_for_status()

    token = _extract_srttkn(getattr(page, "url", ""), getattr(page, "text", ""))
    form_action = ""
    try:
        form_action, _ = _extract_form(getattr(page, "text", "") or "", "idb")
    except Exception:
        form_action = ""
    page_url = getattr(page, "url", "") or ""
    referer = (
        page_url
        if "srttkn=" in page_url
        else urljoin(
            MAILCOM_ACCOUNT_BASE,
            f"{MAILCOM_ACCOUNT_PASSWORD_PATH}?1&srttkn={quote(token)}",
        )
    )
    if form_action:
        post_url = urljoin(page_url or MAILCOM_ACCOUNT_BASE, form_action)
        if "saveChanges=" not in post_url:
            separator = "&" if "?" in post_url else "?"
            post_url = f"{post_url}{separator}saveChanges=x"
    else:
        post_url = urljoin(
            MAILCOM_ACCOUNT_BASE,
            f"{MAILCOM_ACCOUNT_PASSWORD_PATH}?1-1.-form&srttkn={quote(token)}&saveChanges=x",
        )
    payload = {
        "editPanel:username": client.username,
        "editPanel:currentPasswordPanel:topWrapper:inputWrapper:input": current_password,
        "editPanel:newPasswordFieldPanel:topWrapper:inputWrapper:input": new_password,
        "editPanel:retypeNewPasswordFieldPanel:topWrapper:inputWrapper:input": new_password,
    }
    headers = _password_headers(referer, accept_language)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    response = session.post(
        post_url,
        data=payload,
        headers=headers,
        timeout=30,
        allow_redirects=True,
    )
    response.raise_for_status()
    text = getattr(response, "text", "") or ""
    if re.search(
        r"(current password is incorrect|passwords do not match|invalid password|errorMessage)",
        text,
        re.I,
    ):
        raise MailComError("mail.com 修改密码失败，页面返回错误提示")


# ============================================================
# 对外公共接口
# ============================================================


def change_account_password(
    account: Account,
    proxy: str = "",
    new_password: str = "",
) -> tuple[Account, str]:
    """修改 mail.com 账号密码。

    与外部 mail_password_change.change_account_password 签名兼容，
    供 scripts/batch_change_gpt_valid_mails.py / 测活号池改密调用。

    Args:
        account: Account(username, password) dataclass
        proxy: 代理 URL；留空走 _mailcom_proxy()
        new_password: 新密码；留空则随机生成 12 位

    Returns:
        (account, new_password)
    """
    generated = not bool((new_password or "").strip())
    new_password = (new_password or "").strip() or generate_mailcom_password(12)
    old_password = account.password
    # 发送变更前：明确打出旧密码与即将提交的随机/指定新密码（测活批量改密入口）
    logger.info(
        "[MailCom][测活/批量改密] 变更前 email=%s old_password=%s "
        "new_password=%s generated=%s (即将发送 passwordChange)",
        account.username,
        old_password,
        new_password,
        generated,
    )
    proxy = proxy or _mailcom_proxy()
    try:
        client = MailComLightClient(
            account.username,
            account.password,
            session=_http_session(proxy=proxy),
        )
        client.login()
        change_mailcom_password(client, account.password, new_password)
    except Exception as exc:
        logger.error(
            "[MailCom][测活/批量改密] 变更失败 email=%s old_password=%s "
            "attempted_new_password=%s err=%s",
            account.username,
            old_password,
            new_password,
            exc,
        )
        raise
    logger.info(
        "[MailCom][测活/批量改密] 变更后 email=%s old_password=%s "
        "new_password=%s status=success",
        account.username,
        old_password,
        new_password,
    )
    return account, new_password


def change_mailcom_password_for_email(
    email: str,
    new_password: str = "",
    proxy: str = "",
) -> str:
    """按邮箱地址改 mail.com 密码，并回写 DB + 内存缓存。

    供注册主流程 / 自动化任务调用：改密成功后立即更新 email_pool.password 与
    mailcom_client._CONTEXT_CACHE，确保后续 wait_for_otp 用新密码登录。

    Args:
        email: mail.com 邮箱地址
        new_password: 新密码；留空则随机生成 12 位
        proxy: 代理 URL；留空走 _mailcom_proxy()

    Returns:
        新密码
    """
    generated = not bool((new_password or "").strip())
    new_password = (new_password or "").strip() or generate_mailcom_password(12)

    # 取当前账号上下文（内存缓存 → DB fallback）
    from core.mailcom_client import get_account_context

    account_ctx = get_account_context(email)
    if account_ctx is None:
        raise MailComError(
            f"未找到 {email} 的 mail.com 账号上下文，无法改密。"
            f"请确认该邮箱已通过 pick_account 领取或已写入邮箱池。"
        )

    current_password = account_ctx.password
    if not current_password:
        raise MailComError(f"{email} 的当前密码为空，无法改密")

    # 发送变更前：先打出变更前密码与即将提交的随机/指定新密码（自动化注册前改密入口）
    logger.info(
        "[MailCom][自动化改密] 变更前 email=%s old_password=%s "
        "new_password=%s generated=%s (即将发送 passwordChange)",
        email,
        current_password,
        new_password,
        generated,
    )

    # 改密
    _proxy = proxy or _mailcom_proxy()
    try:
        client = MailComLightClient(
            email,
            current_password,
            session=_http_session(proxy=_proxy),
        )
        client.login()
        change_mailcom_password(client, current_password, new_password)
    except Exception as exc:
        logger.error(
            "[MailCom][自动化改密] 变更失败 email=%s old_password=%s "
            "attempted_new_password=%s err=%s",
            email,
            current_password,
            new_password,
            exc,
        )
        raise
    logger.info(
        "[MailCom][自动化改密] 变更后 email=%s old_password=%s "
        "new_password=%s status=success",
        email,
        current_password,
        new_password,
    )

    # 回写内存缓存，后续 fetch_latest_otp 会用新密码
    from core.mailcom_client import MailComAccount

    _CONTEXT_CACHE[email] = MailComAccount(email=email, password=new_password)

    # 回写 DB（email_pool.password）
    try:
        from core import db

        db.update_mailcom_email_password(email, new_password)
        logger.info(
            "[MailCom][自动化改密] %s 新密码已回写 DB email_pool.password new_password=%s",
            email,
            new_password,
        )
    except Exception as exc:
        logger.warning(
            "[MailCom][自动化改密] %s 新密码回写 DB 失败（不影响本次注册取件，缓存已更新）: %s",
            email,
            exc,
        )

    return new_password


def maybe_change_mailcom_password_before_register(
    email: str,
    new_password: str = "",
) -> str | None:
    """注册前按需改 mail.com 密码。

    仅当满足以下全部条件时执行改密：
        1. config.email.MAILCOM_CHANGE_PASSWORD_BEFORE_REGISTER 为 True
        2. 邮箱来源解析为 mailcom

    Args:
        email: 注册邮箱
        new_password: 新密码；留空则随机生成 12 位

    Returns:
        新密码；未执行改密则返回 None
    """
    try:
        from config import email as _email_cfg
    except Exception:
        return None

    if not bool(getattr(_email_cfg, "MAILCOM_CHANGE_PASSWORD_BEFORE_REGISTER", False)):
        return None

    # 判断邮箱来源是否 mailcom
    try:
        from core.email_provider import resolve_email_source

        source = resolve_email_source(email)
    except Exception:
        source = ""
    if source != "mailcom":
        return None

    logger.info(
        "[MailCom][自动化改密] 注册前改密触发 email=%s (将生成/使用随机新密码并写变更前/后日志)",
        email,
    )
    return change_mailcom_password_for_email(email, new_password=new_password)


if __name__ == "__main__":
    # 独立调试：python -m core.mail_password_change 'email----password' [new_password]
    import sys as _sys

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
    )
    if len(_sys.argv) < 2:
        print(
            "usage: python -m core.mail_password_change 'email----password' [new_password]"
        )
        _sys.exit(2)
    parts = _sys.argv[1].split("----")
    if len(parts) != 2:
        print(f"2 段格式错: 拿到 {len(parts)} 段")
        _sys.exit(2)
    _email, _old_pwd = parts
    _new_pwd = _sys.argv[2] if len(_sys.argv) > 2 else ""
    _CONTEXT_CACHE[_email] = Account(username=_email, password=_old_pwd)  # type: ignore[assignment]
    try:
        result = change_mailcom_password_for_email(_email, new_password=_new_pwd)
        print(f"新密码: {result}")
    except Exception as ex:
        print(f"ERR: {ex}")
        _sys.exit(1)
