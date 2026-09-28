"""Outlook 邮箱 provider（Graph API + IMAP 双通道）。

从 4 段接码格式（email----password----client_id----refresh_token）出发，
按优先级尝试多种取件方式：
  1. Graph API（HTTP REST，扫 inbox / junkemail / deleteditems）
  2. IMAP XOAUTH2（双服务器轮询 outlook.live.com → outlook.office365.com）
  3. IMAP 密码登录（兜底）

能力：pooled=True（号池 claim / 用完 mark_dead）
      ephemeral=False（地址固定，OpenAI 可能当老号处理）

本文件由 mail_outlook.py 迁移而来，取件逻辑逐字保留未改。
mail_outlook.py 现为转发壳，旧 import 路径继续可用。
"""
from __future__ import annotations

import email as _email
import email.utils as _eu
import imaplib
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Optional

from .base import ConfigField, MailProvider, register, validate_email

logger = logging.getLogger(__name__)

# ──────────────────────── 常量 ────────────────────────

TOKEN_ENDPOINTS = [
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
    "https://login.live.com/oauth20_token.srf",
    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
]

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_FOLDERS = ["inbox", "junkemail", "deleteditems"]

IMAP_SERVERS = ["outlook.live.com", "outlook.office365.com"]

_FROM_DOMAINS = ("openai.com", "auth.openai", "tm.openai", "chatgpt.com", "tm.open")

# 旧常量保留（外部可能 import）
GRAPH_TOKEN_URL = TOKEN_ENDPOINTS[-1]
IMAP_HOST = IMAP_SERVERS[-1]


class FatalOutlookMailError(RuntimeError):
    """Non-retryable Outlook mail error."""


_FATAL_IMAP_ERROR_PATTERNS = (
    "user is authenticated but not connected",
    "authentication failed",
    "authenticate failed",
    "imap xoauth2",
    "invalid_grant",
    "invalid_client",
)


def _is_fatal_imap_error(exc: Exception) -> bool:
    msg = str(exc or "").lower()
    return any(p in msg for p in _FATAL_IMAP_ERROR_PATTERNS)


# ──────────────────────── Microsoft OAuth ────────────────────────


def _request_access_token(refresh_token: str, client_id: str, scope: str) -> dict:
    """尝试多个 token endpoint 换 access_token，返回完整 JSON dict。"""
    last_error = ""
    for endpoint in TOKEN_ENDPOINTS:
        try:
            body = urllib.parse.urlencode({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
                "scope": scope,
            }).encode()
            req = urllib.request.Request(endpoint, data=body)
            resp = urllib.request.urlopen(req, timeout=15)
            data = json.loads(resp.read())
            if data.get("access_token"):
                return data
            last_error = f"no access_token from {endpoint}"
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", errors="replace")[:300]
            last_error = f"HTTP {e.code} {endpoint}: {text}"
            if e.code in (400, 401, 403):
                continue
            raise
        except Exception as e:
            last_error = f"{endpoint}: {e}"
            continue
    raise FatalOutlookMailError(f"token 获取失败 (scope={scope}): {last_error}")


def get_outlook_access_token(refresh_token: str, client_id: str) -> dict:
    """兼容旧调用：用 IMAP scope 换 token。"""
    return _request_access_token(refresh_token, client_id, IMAP_SCOPE)


# ──────────────────────── OTP 抽取 ────────────────────────


def _is_hex_color_context(haystack: str, idx: int) -> bool:
    if idx > 0 and haystack[idx - 1] == "#":
        return True
    before = haystack[max(0, idx - 30):idx]
    return bool(re.search(
        r"(?:color|background|bgcolor|fill|stroke)\s*[:=]\s*[\"']?#?\s*$",
        before, re.IGNORECASE,
    ))


def _extract_otp_from_html(body: str) -> Optional[str]:
    for pat in (
        r"(?:code(?:\s*is)?|verification|one[-\s]*time|verify|kode|verifikasi|代码|验证码|驗證碼)[^\d<>]{0,80}(\d{6})\b",
        r"chatgpt[^\d<>]{0,80}(\d{6})",
        r"openai[^\d<>]{0,80}(\d{6})",
    ):
        for m in re.finditer(pat, body, re.IGNORECASE | re.DOTALL):
            if not _is_hex_color_context(body, m.start(1)):
                return m.group(1)
    for m in re.finditer(r"\b(\d{6})\b", body):
        if not _is_hex_color_context(body, m.start(1)):
            return m.group(1)
    return None


def _check_from_domain(from_str: str) -> bool:
    from_lower = from_str.lower()
    if not any(d in from_lower for d in _FROM_DOMAINS):
        return False
    if "tm1.openai" in from_lower:
        return False
    return True


# ──────────────────────── Graph API 取件 ────────────────────────


def fetch_otp_via_graph(
    email_addr: str,
    refresh_token: str,
    client_id: str,
    timeout: int = 240,
    threshold_ts: float = 0,
    deadline: float = 0,
    target_email: str = "",
) -> str:
    """Graph API 轮询取 OTP。成功返回 6 位 OTP，认证失败抛 FatalOutlookMailError。"""
    if not deadline:
        deadline = time.time() + max(60, timeout)
    if not threshold_ts:
        threshold_ts = time.time() - 300

    data = _request_access_token(refresh_token, client_id, GRAPH_SCOPE)
    access_token = data["access_token"]
    cached_refresh = data.get("refresh_token", refresh_token)
    token_refreshed = False

    seen: set = set()

    while time.time() < deadline:
        for folder in GRAPH_FOLDERS:
            try:
                messages = _graph_list_messages(
                    access_token,
                    folder,
                    timeout=max(1.0, min(8.0, deadline - time.time())),
                )
            except urllib.error.HTTPError as e:
                if e.code == 401 and not token_refreshed:
                    try:
                        data = _request_access_token(
                            cached_refresh, client_id, GRAPH_SCOPE,
                        )
                        access_token = data["access_token"]
                        if data.get("refresh_token"):
                            cached_refresh = data["refresh_token"]
                        token_refreshed = True
                        messages = _graph_list_messages(
                            access_token,
                            folder,
                            timeout=max(1.0, min(8.0, deadline - time.time())),
                        )
                    except FatalOutlookMailError:
                        raise
                    except urllib.error.HTTPError as e2:
                        if e2.code in (401, 403):
                            raise FatalOutlookMailError(
                                f"Graph API no mail permission HTTP {e2.code}"
                            ) from e2
                        logger.debug(f"[outlook-graph] {folder} HTTP {e2.code}")
                        continue
                    except Exception:
                        continue
                elif e.code in (400, 401, 403):
                    raise FatalOutlookMailError(
                        f"Graph API 无权限: HTTP {e.code}"
                    )
                else:
                    logger.debug(f"[outlook-graph] {folder} HTTP {e.code}")
                    continue
            except Exception as e:
                logger.debug(f"[outlook-graph] {folder} 请求异常: {e}")
                continue

            for msg in messages:
                msg_id = msg.get("id", "")
                if not msg_id or msg_id in seen:
                    continue
                seen.add(msg_id)

                received = msg.get("receivedDateTime", "")
                try:
                    dt = datetime.fromisoformat(received.replace("Z", "+00:00"))
                    msg_ts = dt.timestamp()
                except Exception:
                    msg_ts = 0
                if msg_ts and msg_ts < threshold_ts:
                    continue

                from_obj = msg.get("from") or {}
                from_addr = (from_obj.get("emailAddress") or {}).get("address", "")
                if not _check_from_domain(from_addr):
                    continue

                if target_email:
                    to_list = msg.get("toRecipients") or []
                    to_addrs = [
                        (r.get("emailAddress") or {}).get("address", "").lower()
                        for r in to_list
                    ]
                    if target_email.lower() not in to_addrs:
                        continue

                body_content = ""
                body_obj = msg.get("body") or {}
                if body_obj:
                    body_content = body_obj.get("content", "")
                if not body_content:
                    body_content = msg.get("bodyPreview", "")

                otp = _extract_otp_from_html(body_content)
                if otp:
                    logger.info(
                        f"[outlook-graph] {email_addr} OTP={otp} folder={folder}"
                    )
                    return otp

        token_refreshed = False
        time.sleep(4)

    raise TimeoutError(f"outlook Graph OTP timeout for {email_addr}")


def _graph_list_messages(access_token: str, folder: str, timeout: float = 15) -> list:
    params = urllib.parse.urlencode({
        "$top": "15",
        "$orderby": "receivedDateTime DESC",
        "$select": "id,subject,bodyPreview,body,receivedDateTime,from,toRecipients",
    })
    url = f"{GRAPH_BASE}/me/mailFolders/{folder}/messages?{params}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    })
    resp = urllib.request.urlopen(req, timeout=timeout)
    data = json.loads(resp.read())
    value = data.get("value") or []
    return value if isinstance(value, list) else []


# ──────────────────────── IMAP 取件 ────────────────────────


def fetch_otp_via_imap(
    email_addr: str,
    refresh_token: str,
    client_id: str,
    password: str = "",
    timeout: int = 240,
    threshold_ts: float = 0,
    deadline: float = 0,
    target_email: str = "",
) -> str:
    """IMAP 轮询取 OTP（XOAUTH2 优先 + 密码兜底，双服务器轮询）。"""
    if not deadline:
        deadline = time.time() + max(60, timeout)
    if not threshold_ts:
        threshold_ts = time.time() - 300

    seen: set = set()
    cached_token: str = ""
    cached_refresh: str = refresh_token
    cached_at: float = 0.0
    use_xoauth2 = bool(client_id and refresh_token)
    use_password = bool(password)
    folders_to_scan = ["INBOX", "Junk", "Junk Email", "Spam"]
    found_folders: list[str] | None = None

    if not use_xoauth2 and not use_password:
        raise FatalOutlookMailError("无可用 IMAP 凭据")

    while time.time() < deadline:
        M = None
        try:
            # ── 刷新 access_token ──
            if use_xoauth2 and (not cached_token or time.time() - cached_at > 3000):
                try:
                    data = _request_access_token(cached_refresh, client_id, IMAP_SCOPE)
                    cached_token = data["access_token"]
                    cached_at = time.time()
                    if data.get("refresh_token"):
                        cached_refresh = data["refresh_token"]
                except FatalOutlookMailError as e:
                    logger.warning(f"[outlook-imap] XOAUTH2 token 获取失败: {e}，禁用")
                    use_xoauth2 = False
                    cached_token = ""
                    if not use_password:
                        raise
                except Exception as e:
                    logger.warning(f"[outlook-imap] XOAUTH2 token 获取异常: {e}，禁用")
                    use_xoauth2 = False
                    cached_token = ""
                    if not use_password:
                        raise

            # ── 连接 IMAP（多服务器 + 多认证方式）──
            last_err = None
            for host in IMAP_SERVERS:
                if M:
                    break
                if use_xoauth2 and cached_token:
                    try:
                        M = imaplib.IMAP4_SSL(host, 993, timeout=30)
                        auth_str = (
                            f"user={email_addr}\x01"
                            f"auth=Bearer {cached_token}\x01\x01"
                        )
                        M.authenticate("XOAUTH2", lambda x: auth_str.encode())
                    except Exception as e:
                        last_err = e
                        try:
                            M.logout()
                        except Exception:
                            pass
                        M = None
                        if _is_fatal_imap_error(e):
                            logger.info(
                                f"[outlook-imap] XOAUTH2 host={host} failed, "
                                "继续尝试其它 IMAP host"
                            )

                if not M and use_password:
                    try:
                        M = imaplib.IMAP4_SSL(host, 993, timeout=30)
                        M.login(email_addr, password)
                    except Exception as e:
                        last_err = e
                        try:
                            M.logout()
                        except Exception:
                            pass
                        M = None

            if not M:
                if last_err and _is_fatal_imap_error(last_err):
                    raise FatalOutlookMailError(f"IMAP 登录失败: {last_err}")
                raise RuntimeError(f"IMAP 连接失败: {last_err}")

            # ── 探测文件夹（首次） ──
            if found_folders is None:
                try:
                    typ, listing = M.list()
                    names_lower: dict[str, str] = {}
                    for raw in listing or []:
                        if not raw:
                            continue
                        s = (
                            raw.decode(errors="ignore")
                            if isinstance(raw, bytes)
                            else str(raw)
                        )
                        m = re.search(
                            r'"([^"]+)"\s*$', s,
                        ) or re.search(r"\s(\S+)\s*$", s)
                        if m:
                            nm = m.group(1).strip('"')
                            names_lower[nm.lower()] = nm
                    picked: list[str] = []
                    for cand in folders_to_scan:
                        real = names_lower.get(cand.lower())
                        if real and real not in picked:
                            picked.append(real)
                    for k, v in names_lower.items():
                        if (
                            any(x in k for x in ("junk", "spam", "bulk"))
                            and v not in picked
                        ):
                            picked.append(v)
                    if "INBOX" not in picked:
                        picked.insert(0, "INBOX")
                    found_folders = picked
                except Exception as e:
                    logger.warning(f"[outlook-imap] LIST 失败: {e}")
                    found_folders = list(folders_to_scan)

            # ── 扫描邮件 ──
            for folder in found_folders:
                try:
                    sel_arg = f'"{folder}"' if " " in folder else folder
                    typ, _ = M.select(sel_arg, readonly=True)
                    if typ != "OK":
                        continue
                except Exception:
                    continue
                try:
                    typ, data = M.search(None, "ALL")
                    ids = data[0].split() if data and data[0] else []
                except Exception as e:
                    logger.warning(
                        f"[outlook-imap] SEARCH 失败 folder={folder}: {e}"
                    )
                    continue
                for mid in reversed(ids[-8:]):
                    key = (folder, mid)
                    if key in seen:
                        continue
                    seen.add(key)
                    try:
                        typ, raw = M.fetch(mid, "(BODY.PEEK[])")
                        msg = _email.message_from_bytes(raw[0][1])
                    except Exception:
                        continue
                    date_str = msg.get("Date") or ""
                    try:
                        msg_ts = _eu.parsedate_to_datetime(date_str).timestamp()
                    except Exception:
                        msg_ts = 0
                    if msg_ts and msg_ts < threshold_ts:
                        continue
                    from_field = (msg.get("From") or "").lower()
                    if not _check_from_domain(from_field):
                        continue
                    if target_email:
                        to_field = (msg.get("To") or "").lower()
                        if target_email.lower() not in to_field:
                            continue
                    text_body = ""
                    for part in msg.walk():
                        if part.get_content_type() in ("text/plain", "text/html"):
                            try:
                                payload = part.get_payload(decode=True) or b""
                                text_body += payload.decode(
                                    part.get_content_charset() or "utf-8",
                                    errors="replace",
                                ) + "\n"
                            except Exception:
                                continue
                    otp = _extract_otp_from_html(text_body)
                    if otp:
                        logger.info(
                            f"[outlook-imap] {email_addr} OTP={otp} "
                            f"folder={folder!r}"
                        )
                        try:
                            M.logout()
                        except Exception:
                            pass
                        return otp
            try:
                M.logout()
            except Exception:
                pass
        except FatalOutlookMailError:
            raise
        except Exception as e:
            if _is_fatal_imap_error(e):
                raise FatalOutlookMailError(
                    f"IMAP 不可用 {email_addr}: {e}"
                ) from e
            logger.warning(f"[outlook-imap] 异常 (重试): {e}")
            if M:
                try:
                    M.logout()
                except Exception:
                    pass
        time.sleep(4)
    raise TimeoutError(f"outlook IMAP OTP timeout for {email_addr}")


# ──────────────────────── MailProvider 适配 ────────────────────────


@register
class OutlookMailProvider(MailProvider):
    """auth_flow / browser_register 通用的 MailProvider 实现。

    构造时直接持有 4 段 outlook 凭证，无 DB / 池子。
    pooled=True 让 auth_flow 在 OpenAI 反欺诈静默拒发 OTP 时 fast-fail，
    外层 register() 自动 claim 下一个号。
    """

    kind = "outlook"
    display_name = "Outlook 接码池"
    pooled = True          # 号是买来的，用完/废了要换下一个
    ephemeral = False      # 地址固定，OpenAI 可能识别为已有账号

    line_segments = 4
    import_hint = "每行一个：email----password----client_id----refresh_token"
    import_placeholder = "xxx@hotmail.com----Pass123----9e5f94bc-xxxx----M.C5xx_xxx"

    config_fields: list[ConfigField] = []   # 凭证来自号池，无全局配置

    def __init__(self, email: str, password: str, client_id: str, refresh_token: str):
        self.email = email
        self.password = password
        self.client_id = client_id
        self.refresh_token = refresh_token
        self.last_persona = None
        self.catch_all_domain = email.split("@", 1)[1]
        self._dead = False

    # ── 构造入口 ─────────────────────────────────────────

    @classmethod
    def from_config(cls, settings: dict, account: Optional[dict] = None):
        if not account:
            raise ValueError("outlook provider 需要从号池 claim 到的 account")
        return cls(
            email=account["email"],
            password=account.get("password", ""),
            client_id=account["client_id"],
            refresh_token=account["refresh_token"],
        )

    @classmethod
    def parse_line(cls, line: str) -> dict:
        """4 段格式：email----password----client_id----refresh_token

        非法行抛 ValueError 说明原因（不返回 None），
        调用方会把原因连同行号报给用户。
        """
        parts = line.split("----")
        if len(parts) != 4:
            raise ValueError(
                f"需要 4 段（email----password----client_id----refresh_token），"
                f"实际 {len(parts)} 段"
            )
        email, password, client_id, refresh = (p.strip() for p in parts)
        validate_email(email)
        if not client_id:
            raise ValueError("client_id 为空")
        if len(refresh) < 20:
            raise ValueError(f"refresh_token 太短（{len(refresh)} 字符，至少 20）")
        return {
            "email": email.lower(),
            "password": password,
            "client_id": client_id,
            "refresh_token": refresh,
            "kind": cls.kind,
        }

    # ── 号池语义 ─────────────────────────────────────────

    @property
    def exhausted(self) -> bool:
        return self._dead

    def mark_dead(self, reason: str = "") -> None:
        logger.warning(f"[mail] outlook {self.email} mark dead: {reason}")
        self._dead = True

    # ── 收发 ────────────────────────────────────────────

    def create_mailbox(self) -> str:
        logger.info(f"[mail] 使用 outlook 账号: {self.email}")
        return self.email

    def wait_for_otp(
        self,
        email_addr: str,
        timeout: int = 120,
        issued_after: Optional[float] = None,
    ) -> str:
        method_timeout = max(1, int(timeout))
        strict_threshold = (issued_after - 5) if issued_after else (time.time() - 5)

        has_oauth = bool(self.client_id and self.refresh_token)
        has_password = bool(self.password)
        graph_error: Exception | None = None

        if has_oauth:
            try:
                logger.info(
                    f"[mail] Graph API 取 OTP -> {email_addr} "
                    f"(timeout={method_timeout}s, IMAP兜底=Y)"
                )
                return fetch_otp_via_graph(
                    self.email,
                    self.refresh_token,
                    self.client_id,
                    deadline=time.time() + method_timeout,
                    threshold_ts=strict_threshold,
                    target_email=email_addr,
                )
            except Exception as e:
                graph_error = e
                logger.warning(
                    f"[mail] Graph 失败 ({type(e).__name__}: {e})，"
                    f"切换 IMAP (timeout={method_timeout}s)"
                )

        logger.info(
            f"[mail] IMAP 取 OTP -> {email_addr} "
            f"(timeout={method_timeout}s, "
            f"xoauth2={'Y' if has_oauth else 'N'} "
            f"password={'Y' if has_password else 'N'})"
        )
        try:
            return fetch_otp_via_imap(
                self.email,
                self.refresh_token,
                self.client_id,
                password=self.password if has_password else "",
                timeout=method_timeout,
                threshold_ts=strict_threshold,
                target_email=email_addr,
            )
        except Exception as e:
            if graph_error is not None:
                logger.warning(
                    f"[mail] IMAP 也失败 ({type(e).__name__}: {e})；"
                    f"Graph 先前错误: {type(graph_error).__name__}: {graph_error}"
                )
            raise

