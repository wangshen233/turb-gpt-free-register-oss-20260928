# -*- coding: utf-8 -*-
"""TLS / HTTP2 指纹唯一化 —— 让每个账号的 JA3 + Akamai 都不同。

## 为什么要有这个模块

create_http_session(impersonate="chrome146") 给的是一套**固定**指纹：
全世界所有跑 curl_cffi 的协议注册机，JA3 都是
a912eb0417c28969ea568912bb1dd121，Akamai 都是 52d84b11737d980aef85。

Cloudflare / OpenAI 的 WAF 只要把这一个 JA3 拉黑，所有协议机一起死。
实测这批越南住宅 IP 上，同一 IP 用固定指纹反复打 -> 403/200 随机横跳，
两轮 60 次仅 11 次通过（18%）。这就是"指纹废了"的真相。

## 怎么解

curl_cffi 0.16 的 extra_fp 暴露了 JA3 里真正能变的几个维度：

    tls_permute_extensions    bool        扩展顺序随机化（直接改 JA3）
    tls_grease                bool        插入 GREASE 填充值
    tls_signature_algorithms  list[str]   签名算法列表与顺序
    tls_record_size_limit     int
    http2_stream_weight       int         改 HTTP/2 指纹（Akamai）
    http2_stream_exclusive    int
    http2_no_priority         bool
    header_order              str         请求头顺序

实测（tls.browserleaks.com）四组参数得到四个不同的 JA3，验证有效：

    基线 chrome146      ja3=a912eb0417c28969ea568912bb1dd121
    permute_extensions  ja3=9ce613396523f9dc7eb8660c47a96489
    grease+permute      ja3=2c3c99e38b5083351754cd3dc455a4cf
    sigalg 重排         ja3=064f9b37a28d638b6e8fa4d4d570fedd

用法：
    fp = unique_tls_fingerprint()          # 每次调用都不一样
    session = create_http_session(proxy=..., tls_fp=fp)
"""
from __future__ import annotations

import random

# Chrome 真实使用的签名算法集合（JA3 第 4 段）。真实 Chrome 的集合是固定的，
# 但**顺序**在不同版本/平台上不同，且并非所有客户端的顺序都被收录进指纹库。
_CHROME_SIG_ALGS = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
]

# HTTP/2 优先级参数的真实取值域（Chrome 用 255/1，但服务端少见 100~256 的其它值）
_H2_WEIGHTS = [255, 256, 220, 200, 147, 110, 100, 64, 42, 16]
_H2_EXCLUSIVE = [1, 0]


def unique_tls_fingerprint(*, seed=None, permute=True, grease=True,
                           vary_sigalg=True, vary_http2=True):
    """生成一套随机的 JA3 / HTTP2 指纹参数（直接喂给 curl_cffi 的 extra_fp）。

    同一次注册内必须固定（真实浏览器握手参数不会中途变），所以调用方
    生成一次、存进指纹 dict、整个流程复用。
    """
    r = random.Random(seed)
    fp = {}

    if permute:
        # 扩展顺序随机化 —— 这是改 JA3 最有效的一维
        fp["tls_permute_extensions"] = True

    if grease:
        fp["tls_grease"] = True

    if vary_sigalg:
        # 保序集合不变、顺序打乱：仍然是合法的 Chrome 签名算法集合，
        # 但 JA3 第 4 段的哈希不同。
        algs = list(_CHROME_SIG_ALGS)
        r.shuffle(algs)
        fp["tls_signature_algorithms"] = algs

    if vary_http2:
        # 只动优先级，不动 SETTINGS —— 保持 HTTP/2 帧结构合法
        fp["http2_stream_weight"] = r.choice(_H2_WEIGHTS)
        fp["http2_stream_exclusive"] = r.choice(_H2_EXCLUSIVE)

    fp["_summary"] = "permute=%s grease=%s sigalg=%s h2w=%s" % (
        permute, grease, "shuffled" if vary_sigalg else "fixed",
        fp.get("http2_stream_weight"),
    )
    return fp


def merge_extra_fp(tls_fp, extra=None):
    """把唯一化参数与已有的 extra_fp 合并（去掉内部 _summary 键）。"""
    out = {}
    if tls_fp:
        out.update({k: v for k, v in tls_fp.items() if not k.startswith("_")})
    if extra:
        out.update(extra)
    return out or None

# ---------------------------------------------------------------------------
# HTTP/2（Akamai）指纹唯一化
#
# 为什么还要动这个：Cloudflare 的 bot score 同时看 TLS(JA3) 和 HTTP/2(Akamai)。
# 光换 JA3、Akamai 还是那个全球共用的 52d84b11737d980aef85，等于只堵了一半。
#
# curl_cffi 的 akamai 参数格式（竖线分隔四段）：
#     SETTINGS|WINDOW_UPDATE|PRIORITY|伪头顺序
# 例：1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p
#
# 唯一化策略（只动"真机本来就会变"的维度，不编造不可能的值）：
#   * SETTINGS 各参数的**取值**保持 Chrome 真值不动
#   * SETTINGS 的**排列顺序**随机化 —— 不同 Chrome 版本/平台顺序确实不同
#   * ENABLE_PUSH(2:0) 随机**带或不带** —— HTTP/2 push 已废弃，新版 Chrome 会省略
#   * WINDOW_UPDATE / PRIORITY / 伪头顺序保持 Chrome 真值
#
# 实测：6 组参数得到 5 个不同的 Akamai 哈希，且 JA3 一并改变。
# ---------------------------------------------------------------------------

# Chrome 的 HTTP/2 SETTINGS 真值（取值域不动，只动顺序与有无）
_CHROME_H2_SETTINGS = {
    1: 65536,      # HEADER_TABLE_SIZE
    2: 0,          # ENABLE_PUSH（新版 Chrome 已省略）
    3: 1000,       # MAX_CONCURRENT_STREAMS
    4: 6291456,    # INITIAL_WINDOW_SIZE
    6: 262144,     # MAX_HEADER_LIST_SIZE
}
_CHROME_H2_WINDOW_UPDATE = 15663105
_CHROME_H2_PRIORITY = 0
_CHROME_H2_PSEUDO_ORDER = "m,a,s,p"


def unique_akamai_fingerprint(*, seed=None, drop_push_prob=0.5):
    """生成一个 Chrome 可信但**唯一**的 HTTP/2（Akamai）指纹串。"""
    r = random.Random(seed)

    ids = [1, 2, 3, 4, 6]
    # HTTP/2 push 已废弃：真机新版本不带 ENABLE_PUSH
    if r.random() < drop_push_prob:
        ids = [i for i in ids if i != 2]
    r.shuffle(ids)

    settings = ";".join("%d:%d" % (i, _CHROME_H2_SETTINGS[i]) for i in ids)
    return "%s|%d|%d|%s" % (
        settings, _CHROME_H2_WINDOW_UPDATE, _CHROME_H2_PRIORITY,
        _CHROME_H2_PSEUDO_ORDER,
    )


def unique_transport_fingerprint(*, seed=None):
    """一次给全：TLS(extra_fp) + HTTP/2(akamai)。同任务内固定。"""
    s = seed if seed is not None else random.randrange(1 << 62)
    return {
        "extra_fp": unique_tls_fingerprint(seed=s),
        "akamai": unique_akamai_fingerprint(seed=s ^ 0x5DEECE66D),
    }

