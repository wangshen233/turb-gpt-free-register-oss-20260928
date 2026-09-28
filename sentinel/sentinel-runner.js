#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");
const { performance } = require("node:perf_hooks");
const tzProfile = require("./tz_profile");

// ---------- SDK hook 硬校验 ----------
// 这三处替换是整条 Sentinel 链路的命门：外面（node）能拿到 SDK 内部函数，
// 全靠往下载到的 sdk.js 里插出口。
//
// ⚠️ OpenAI 会在**同一个版本 URL 下原地重建 sdk.js**：字节数与 SHA 都没变，
//    内部标识符整体重命名（2026-09 实测，老锚点 \`var P=new _;\` 就是这么被打死的）。
//    旧代码这里是裸的 String.replace() / if (includes) {} —— **失配无声无息**，
//    只在回退分支以「PoW 算不出来」的假象暴露，白排查一轮。
//    现在一律走 mustReplace()：失配立刻 exit 3，并配合加载后的 POST-LOAD CHECK 兜底。
const HOOK_EXIT_CODE = 3;

function mustReplace(src, pattern, replacement, label) {
  const hits = src.split(pattern).length - 1;
  if (hits === 0) {
    process.stderr.write(
      "[sentinel-hook] MISS " + label + ": 锚点未命中 -> " + JSON.stringify(pattern) + "\n" +
      "[sentinel-hook] sdk.js 疑似被原地重建，hook 已失效；拒绝继续（exit " + HOOK_EXIT_CODE + "），\n" +
      "[sentinel-hook] 避免产出假 token 把真因掩盖成「PoW 失败」。\n"
    );
    process.exit(HOOK_EXIT_CODE);
  }
  if (hits > 1) {
    // 多命中不致命（String.replace 只换第一处），POST-LOAD CHECK 会兜底。
    process.stderr.write("[sentinel-hook] WARN " + label + ": 锚点命中 " + hits + " 次，只替换第一处\n");
  }
  return src.replace(pattern, replacement);
}

// 给**已经确认失效**的历史锚点用：打一行醒目警告但不中断。
// 只有在「该补丁对应的代码路径在当前 sdk.js 里根本不存在」时才允许用它 ——
// 否则就是在给静默降级开后门，正是本文件要根除的东西。
function optionalReplace(src, pattern, replacement, label) {
  if (src.includes(pattern)) return src.replace(pattern, replacement);
  process.stderr.write(
    "[sentinel-hook] STALE " + label + ": 锚点已不存在 -> " + JSON.stringify(pattern) + "\n" +
    "[sentinel-hook] 该补丁是历史 SDK 版本的遗留，当前 sdk.js 里没有对应代码路径，跳过。\n"
  );
  return src;
}

// ---------- 画像兜底：必须与 config/browser.py + config/openai_protocol.py 同源 ----------
// Python 端（core/sentinel_runner.py）总是显式传参；这里的默认值只在直接跑 runner 时生效。
// 默认值必须与 Python 端一致，避免出现 TLS/Python = Windows + Chrome142 而 JS navigator = macOS 的分裂指纹。
const FALLBACK_BUILD_ID = "prod-8bfe9e3526fbf9900f9332d46fef7bc0065c4478";
const DEFAULT_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
const DEFAULT_SEC_CH_UA = '"Chromium";v="145", "Not?A_Brand";v="24", "Google Chrome";v="145"';
const DEFAULT_SEC_CH_UA_FULL_VERSION_LIST =
  '"Chromium";v="145.0.0.0", "Not?A_Brand";v="24.0.0.0", "Google Chrome";v="145.0.0.0"';

function readArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const item = argv[i];
    if (!item.startsWith("--")) continue;
    const key = item.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      args[key] = "1";
      continue;
    }
    args[key] = next;
    i++;
  }
  return args;
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function parseJson(text, source) {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${source} 不是合法 JSON：${error.message}`);
  }
}

function pick(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return "";
}

function truthy(value) {
  return value === true || value === "1" || value === "true" || value === "yes";
}

function readConfig(args) {
  const explicitPath = args.config || process.env.SENTINEL_CONFIG;
  const candidates = explicitPath
    ? [path.resolve(explicitPath)]
    : [
        path.resolve(process.cwd(), "sentinel.config.json"),
        path.resolve(process.cwd(), "tools", "sentinel.config.json"),
        path.resolve(__dirname, "sentinel.config.json"),
        path.resolve(__dirname, "..", "sentinel.config.json"),
      ];

  for (const filePath of candidates) {
    if (!fs.existsSync(filePath)) continue;
    return {
      path: filePath,
      data: parseJson(fs.readFileSync(filePath, "utf8"), filePath),
    };
  }

  return { path: null, data: {} };
}

function configGetter(config) {
  return (...keys) => {
    for (const key of keys) {
      if (config[key] !== undefined && config[key] !== null && config[key] !== "") {
        return config[key];
      }
    }
    return "";
  };
}

function normalizeList(value, fallback) {
  const source = Array.isArray(value) ? value.join(",") : pick(value, fallback);
  return String(source)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseSecChBrands(value, major = "") {
  const text = String(value || "").trim();
  if (!text) {
    return [
      { brand: "Not)A;Brand", version: "8" },
      { brand: "Chromium", version: String(major || "") },
      { brand: "Google Chrome", version: String(major || "") },
    ];
  }
  const out = [];
  const re = /"([^"]+)"\s*;\s*v="([^"]+)"/g;
  let m;
  while ((m = re.exec(text))) out.push({ brand: m[1], version: m[2] });
  return out.length ? out : text.split(",").map((part) => ({ brand: part.trim(), version: String(major || "") })).filter((x) => x.brand);
}

function xorDecode(text, key) {
  let output = "";
  const decoded = atobBinary(text);
  for (let i = 0; i < decoded.length; i++) {
    output += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return output;
}

function xorDecodeFromBinary(binary, key) {
  let output = "";
  for (let i = 0; i < binary.length; i++) {
    output += String.fromCharCode(binary.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return output;
}

function decodeDx(dx, proof) {
  return JSON.parse(xorDecode(dx, proof));
}

function normalizeChallenge(raw) {
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return trimmed;
    raw = parseJson(trimmed, "challenge 字符串");
  }

  const candidates = [
    raw?.cachedChatReq,
    raw?.result?.cachedChatReq,
    raw?.data?.cachedChatReq,
    raw?.data,
    raw,
  ];

  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== "object") continue;
    if (candidate.proofofwork || candidate.token || candidate.turnstile || candidate.so) {
      return candidate;
    }
  }

  throw new Error("challenge 缺少 cachedChatReq/proofofwork/token 字段，无法喂给 SDK");
}

function readChallengeFile(filePath) {
  const absolutePath = path.resolve(filePath);
  const raw = fs.readFileSync(absolutePath, "utf8");
  return normalizeChallenge(parseJson(raw, absolutePath));
}

const OFFICIAL_CHALLENGE_URL = "https://chatgpt.com/backend-api/sentinel/req";

function headerMapFromEnv(options = {}) {
  const headers = {
    accept: "*/*",
    "content-type":
      options.contentType ||
      (options.ignoreEnv ? "" : process.env.SENTINEL_CONTENT_TYPE) ||
      "text/plain;charset=UTF-8",
  };
  const cookie =
    options.cookie ||
    (options.ignoreEnv ? "" : process.env.SENTINEL_COOKIE || process.env.CHATGPT_COOKIE);
  const authorization =
    options.bearer ||
    (options.ignoreEnv ? "" : process.env.SENTINEL_AUTHORIZATION || process.env.CHATGPT_BEARER_TOKEN);
  const userAgent = options.userAgent || (options.ignoreEnv ? "" : process.env.SENTINEL_USER_AGENT);

  if (cookie) headers.cookie = cookie;
  if (authorization) {
    headers.authorization = authorization.toLowerCase().startsWith("bearer ")
      ? authorization
      : `Bearer ${authorization}`;
  }
  if (userAgent) {
    headers["user-agent"] = userAgent;
  }
  if (options.pageUrl) headers.referer = options.pageUrl;
  if (options.origin) headers.origin = options.origin;
  if (options.deviceId) headers["oai-device-id"] = options.deviceId;
  if (process.env.SENTINEL_HEADERS_JSON) {
    Object.assign(headers, parseJson(process.env.SENTINEL_HEADERS_JSON, "SENTINEL_HEADERS_JSON"));
  }
  return headers;
}

function assertAllowedChallengeHost(challengeUrl, officialMode) {
  const host = new URL(challengeUrl).hostname.toLowerCase();
  const allowed = (process.env.SENTINEL_ALLOW_HOST || "")
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);

  if ((host === "chatgpt.com" || host.endsWith(".chatgpt.com")) && !officialMode && !allowed.includes(host)) {
    throw new Error(
      "为避免误打真实生产接口，默认不请求 chatgpt.com。若这是比赛授权接口，请使用 --official 或设置 SENTINEL_ALLOW_HOST=chatgpt.com。"
    );
  }
}

async function fetchChallengeViaCurl(challengeUrl, body, headers, proxy) {
  const { spawnSync } = require("node:child_process");
  const helper = path.resolve(__dirname, "..", "tools", "sentinel_live_req.py");
  const payload = JSON.stringify({
    url: challengeUrl,
    body,
    headers,
    proxy: proxy || "",
    impersonate: "chrome142",
  });
  const proc = spawnSync("python", [helper], {
    input: payload,
    encoding: "utf8",
    windowsHide: true,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (proc.error) throw proc.error;
  if (proc.status !== 0) {
    const err = String(proc.stderr || proc.stdout || "");
    const tail = err.split("\n").map((x) => x.trim()).filter(Boolean).slice(-1)[0] || "";
    throw new Error(`live challenge 失败 last=${tail.slice(0, 300)} | head=${err.slice(0, 200)}`);
  }
  return proc.stdout || "";
}

async function fetchChallenge(challengeUrl, flow, proof, deviceId, options = {}) {
  assertAllowedChallengeHost(challengeUrl, options.officialMode);
  const hasCookie = Boolean(
    options.cookie || (options.ignoreEnv ? "" : process.env.SENTINEL_COOKIE || process.env.CHATGPT_COOKIE)
  );
  const hasBearer = Boolean(
    options.bearer ||
      (options.ignoreEnv ? "" : process.env.SENTINEL_AUTHORIZATION || process.env.CHATGPT_BEARER_TOKEN)
  );
  if (options.officialMode && !hasCookie && !hasBearer) {
    throw new Error("官方接口模式至少需要 Cookie 或 Bearer；请传 --cookie 或 --bearer。");
  }
  const body = JSON.stringify({ p: proof, id: deviceId, flow });
  const headers = headerMapFromEnv({
    pageUrl: options.pageUrl,
    origin: new URL(challengeUrl).origin,
    userAgent: options.userAgent,
    deviceId,
    cookie: options.cookie,
    bearer: options.bearer,
    contentType: options.contentType || "text/plain;charset=UTF-8",
    ignoreEnv: options.ignoreEnv,
  });
  let text = "";
  if (options.proxy) {
    text = await fetchChallengeViaCurl(challengeUrl, body, headers, options.proxy);
  } else {
    const response = await fetch(challengeUrl, { method: "POST", headers, body });
    text = await response.text();
    if (!response.ok) {
      throw new Error(`challenge API 返回 HTTP ${response.status}：${text.slice(0, 300)}`);
    }
  }
  const parsed = normalizeChallenge(text);
  if (parsed && typeof parsed === "object") parsed._requirements_p = String(proof || "");
  return parsed;
}

function createEventTarget() {
  const listeners = new Map();
  return {
    addEventListener(type, listener) {
      const bucket = listeners.get(type) || [];
      bucket.push(listener);
      listeners.set(type, bucket);
    },
    removeEventListener(type, listener) {
      const bucket = listeners.get(type) || [];
      listeners.set(
        type,
        bucket.filter((item) => item !== listener)
      );
    },
    dispatchEvent(event) {
      const bucket = listeners.get(event.type) || [];
      for (const listener of [...bucket]) listener.call(this, event);
    },
  };
}

function btoaBinary(value) {
  return Buffer.from(String(value), "binary").toString("base64");
}

function atobBinary(value) {
  return Buffer.from(String(value), "base64").toString("binary");
}

function createStorage() {
  const values = new Map();
  return {
    get length() {
      return values.size;
    },
    key(index) {
      return [...values.keys()][Number(index)] ?? null;
    },
    getItem(key) {
      const name = String(key);
      return values.has(name) ? values.get(name) : null;
    },
    setItem(key, value) {
      values.set(String(key), String(value));
    },
    removeItem(key) {
      values.delete(String(key));
    },
    clear() {
      values.clear();
    },
  };
}

function createDomRect(width = 0, height = 0) {
  return {
    x: 0,
    y: 0,
    width,
    height,
    top: 0,
    left: 0,
    right: width,
    bottom: height,
    toJSON() {
      return {
        x: this.x,
        y: this.y,
        width: this.width,
        height: this.height,
        top: this.top,
        left: this.left,
        right: this.right,
        bottom: this.bottom,
      };
    },
  };
}


function createDomTokenList(initial = []) {
  const tokens = new Set(initial);
  const api = {
    add(...items) { for (const item of items) if (item) tokens.add(String(item)); },
    remove(...items) { for (const item of items) tokens.delete(String(item)); },
    contains(item) { return tokens.has(String(item)); },
    toggle(item, force) {
      const token = String(item);
      const shouldAdd = force === undefined ? !tokens.has(token) : Boolean(force);
      if (shouldAdd) tokens.add(token); else tokens.delete(token);
      return shouldAdd;
    },
    replace(oldToken, newToken) {
      if (!tokens.has(String(oldToken))) return false;
      tokens.delete(String(oldToken));
      tokens.add(String(newToken));
      return true;
    },
    item(index) { return [...tokens][Number(index)] || null; },
    get length() { return tokens.size; },
    toString() { return [...tokens].join(" "); },
    [Symbol.iterator]() { return tokens[Symbol.iterator](); },
  };
  Object.defineProperty(api, Symbol.toStringTag, { value: "DOMTokenList" });
  return api;
}

function createStyleDeclaration() {
  const values = Object.create(null);
  return {
    get cssText() {
      return Object.entries(values).map(([k, v]) => `${k}: ${v};`).join(" ");
    },
    set cssText(text) {
      for (const part of String(text || "").split(";")) {
        const idx = part.indexOf(":");
        if (idx > 0) this.setProperty(part.slice(0, idx).trim(), part.slice(idx + 1).trim());
      }
    },
    get length() { return Object.keys(values).length; },
    item(index) { return Object.keys(values)[Number(index)] || ""; },
    getPropertyValue(name) { return values[String(name)] || ""; },
    setProperty(name, value) { values[String(name)] = String(value); this[String(name)] = String(value); },
    removeProperty(name) { const key = String(name); const old = values[key] || ""; delete values[key]; delete this[key]; return old; },
  };
}

function createElementNode(tagName, ownerDocument, rect = createDomRect()) {
  const target = createEventTarget();
  const children = [];
  const attrs = new Map();
  const dataset = {};
  const element = {
    nodeType: 1,
    nodeName: String(tagName).toUpperCase(),
    tagName: String(tagName).toUpperCase(),
    ownerDocument,
    parentNode: null,
    parentElement: null,
    children,
    childNodes: children,
    firstChild: null,
    lastChild: null,
    style: createStyleDeclaration(),
    dataset,
    classList: createDomTokenList(),
    textContent: "",
    innerHTML: "",
    appendChild(node) {
      children.push(node);
      node.parentNode = element;
      node.parentElement = element;
      element.firstChild = children[0] || null;
      element.lastChild = children[children.length - 1] || null;
      return node;
    },
    removeChild(node) {
      const index = children.indexOf(node);
      if (index >= 0) children.splice(index, 1);
      if (node) { node.parentNode = null; node.parentElement = null; }
      element.firstChild = children[0] || null;
      element.lastChild = children[children.length - 1] || null;
      return node;
    },
    insertBefore(node, before) {
      const index = children.indexOf(before);
      if (index < 0) return this.appendChild(node);
      children.splice(index, 0, node);
      node.parentNode = element;
      node.parentElement = element;
      element.firstChild = children[0] || null;
      element.lastChild = children[children.length - 1] || null;
      return node;
    },
    remove() { if (element.parentNode?.removeChild) element.parentNode.removeChild(element); },
    setAttribute(name, value) {
      const key = String(name);
      const val = String(value);
      attrs.set(key, val);
      if (key === "class") element.classList = createDomTokenList(val.split(/\s+/).filter(Boolean));
      if (key === "id") element.id = val;
      if (key.startsWith("data-")) {
        const prop = key.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        dataset[prop] = val;
      }
    },
    getAttribute(name) { return attrs.get(String(name)) ?? null; },
    hasAttribute(name) { return attrs.has(String(name)); },
    removeAttribute(name) { attrs.delete(String(name)); },
    getAttributeNames() { return [...attrs.keys()]; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    matches() { return false; },
    closest() { return null; },
    getBoundingClientRect() { return rect; },
    addEventListener: target.addEventListener,
    removeEventListener: target.removeEventListener,
    dispatchEvent: target.dispatchEvent,
    click() { target.dispatchEvent.call(element, { type: "click", target: element }); },
  };
  Object.defineProperty(element, "attributes", {
    get() { return [...attrs].map(([name, value]) => ({ name, value, nodeName: name, nodeValue: value, valueOf: () => value })); },
  });
  return element;
}


function unwrapLongSo(value) {
  if (typeof value === "string") {
    const text = value.trim();
    if (text.startsWith("{") && text.endsWith("}")) {
      try {
        const nested = JSON.parse(text);
        if (typeof nested?.so === "string" && nested.so.length >= 400) return nested.so;
      } catch {}
    }
    return text.length >= 400 ? text : "";
  }
  if (value && typeof value === "object" && typeof value.so === "string" && value.so.length >= 400) {
    return value.so;
  }
  return "";
}

function isDxErrorBlob(value) {
  if (typeof value !== "string" || value.length < 8) return false;
  try {
    const decoded = Buffer.from(value, "base64").toString("utf8");
    return /SyntaxError|Expected ','|JSON\.parse|Unexpected token/i.test(decoded);
  } catch {
    return false;
  }
}

function soDxLog(msg) {
  try { process.stderr.write(`so-dx: ${msg}\n`); } catch {}
}

// 诊断：挑战的 dx 里会让 SDK 去读一批 __oai_so_* 环境键。假窗口没定义的键会被序列化时跳过，
// 于是 so/t 载荷比真浏览器薄（实测 t 1036 vs 真浏览器 1348）。这里把「读了但没定义」的键
// 连同它在 dx 里的上下文一起打出来，方便照着上下文补类型/取值。
function soDxReportMissing(decoded, names, scope, tag) {
  try {
    const soKeys = Object.keys(scope).filter((k) => k.indexOf("__oai_so_") === 0);
    soDxLog(
      `${tag} scope type=${typeof scope} isWindow=${scope === scope.window} soKeys=${soKeys.length} ` +
      `wl=${typeof scope.__oai_so_wl} m=${typeof scope.__oai_so_m} ` +
      `hasOwnWl=${Object.prototype.hasOwnProperty.call(scope, "__oai_so_wl")}`
    );
    const missing = names.filter((name) => scope[name] === undefined);
    if (!missing.length) {
      soDxLog(`${tag}: all ${names.length} keys defined`);
      return;
    }

    soDxLog(`${tag}: MISSING ${missing.length}/${names.length} -> ${missing.join(",")}`);
    for (const name of missing) {
      const idx = decoded.indexOf(name);
      const ctx = decoded.slice(Math.max(0, idx - 80), idx + 70).replace(/\s+/g, " ");
      soDxLog(`${tag} ctx ${name}: ...${ctx}...`);
    }
  } catch (error) {
    soDxLog(`${tag} report fail ${error && error.message || error}`);
  }
}

function pickLongerSo(...values) {
  const ok = values
    .map((value) => unwrapLongSo(value))
    .filter((text) => text && !isDxErrorBlob(text));
  ok.sort((a, b) => b.length - a.length);
  return ok[0] || "";
}

async function mintSessionObserverBlob(vmContext, challenge, tokenParsed) {
  const existing = unwrapLongSo(tokenParsed?.so);
  const so = challenge?.so;
  if (!so || so.required !== true || !so.collector_dx || !so.snapshot_dx) return pickLongerSo(existing);
  const g = vmContext.window || vmContext.globalThis || vmContext;
  const Et = vmContext.Et || g.Et;
  const qt = vmContext.qt || g.qt;
  const F = vmContext.F || g.F;
  if (typeof Et !== "function" || typeof qt !== "function") {
    soDxLog(`Et/qt missing Et=${typeof Et} qt=${typeof qt}`);
    return pickLongerSo(existing);
  }
  try {
    const key = String(challenge?._requirements_p || (typeof F === "function" ? (F(challenge) || "") : "") || "");
    soDxLog(`xor key type=${typeof key} len=${key.length} prefix=${key.slice(0, 8)} src=${challenge?._requirements_p ? "python_p" : "F(challenge)"}`);
    const D = g.D || vmContext.D;
    if (typeof D === "function" && key) {
      try { D(challenge, key); } catch {}
    }
    try {
      const decodedSnapshot = xorDecode(String(so.snapshot_dx || ""), key);
      const names = [...new Set((decodedSnapshot.match(/__oai_so_[A-Za-z0-9_]+/g) || []))];
      soDxLog("snapshot_dx reads=" + names.length + " " + names.join(","));
      soDxReportMissing(decodedSnapshot, names, g, "snapshot");
      const decodedCollector = xorDecode(String(so.collector_dx || ""), key);
      const cnames = [...new Set((decodedCollector.match(/__oai_so_[A-Za-z0-9_]+/g) || []))];
      soDxLog("collector_dx reads=" + cnames.length + " " + cnames.join(","));
      soDxReportMissing(decodedCollector, cnames, g, "collector");
    } catch (error) {
      soDxLog("snapshot decode fail " + (error && error.message || error));
    }
    reapplySessionObserverTelemetry(g);
    await Promise.resolve(Et(so.collector_dx, key));
    // 短 so (~540) 是 token() 立刻 snapshot 的结果；HAR 是 624/700，等 collector 再采一轮。
    await new Promise((resolve) => setTimeout(resolve, 8000));
    reapplySessionObserverTelemetry(g);
    const blob = await Promise.resolve(qt(so.snapshot_dx));
    const minted = typeof blob === "string" ? blob : unwrapLongSo(blob);
    soDxLog(`snapshot type=${typeof blob} minted=${String(minted || "").length} existing=${existing.length} err=${isDxErrorBlob(minted)}`);
    const chosen = pickLongerSo(minted, existing);
    soDxLog(`chosen so len=${chosen.length}`);
    return chosen;
  } catch (error) {
    soDxLog(`Et/qt failed: ${error?.message || error}`);
  }
  return pickLongerSo(existing);
}

// 时区实现已抽到 sentinel/tz_profile.js（唯一真源，tools/sentinel_tzprobe.js 跑的就是它）。
//
// 旧实现有两个硬伤（2026-09-22 实测 + 真 Chrome 148 基线比对后修）：
//   1) tzName 直接取 options.timezoneName —— Python 端默认传 "Japan Standard Time"，
//      是个**写死的英文 ICU 名**，完全不管画像 locale。页面 locale 是 vi-VN 时真 Chrome
//      报 "(Giờ Đông Dương)"，我们报 "(Japan Standard Time)"，一眼假。
//   2) offsetMinutes 直接取 options.timezoneOffsetMinutes —— 写死数字，不跟 IANA 名、
//      不跟夏令时。现在按 IANA 名算「当前这一刻」的偏移。
//
// ⚠️ options.timezoneName / options.timezoneOffsetMinutes 现在**被忽略**（只做兼容占位）。
//    显式传了不一致的值只会在 SENTINEL_TZ_DEBUG 下打一行警告，不再影响输出。
function applyDateTimezone(DateCtor, options) {
  const result = tzProfile.applyDateTimezone(DateCtor, options);
  if (process.env.SENTINEL_TZ_DEBUG) {
    const p = result.profile;
    const suppliedName = options?.timezoneName;
    const suppliedOffset = Number(options?.timezoneOffsetMinutes);
    if (suppliedName && suppliedName !== p.paren) {
      process.stderr.write("[tz] 忽略 options.timezoneName=" + JSON.stringify(suppliedName)
        + "，改用 ICU(" + p.locale + ")=" + JSON.stringify(p.paren) + "\n");
    }
    if (Number.isFinite(suppliedOffset) && suppliedOffset !== p.offsetMin) {
      process.stderr.write("[tz] 忽略 options.timezoneOffsetMinutes=" + suppliedOffset
        + "，改用 IANA(" + p.target + ")=" + p.offsetMin + "\n");
    }
    process.stderr.write("[tz] " + JSON.stringify(p) + "\n");
  }
  return result;
}

const CHROME_WINDOW_PROP_NAMES = [
  "AbortSignal","AbsoluteOrientationSensor","Accelerometer","AnalyserNode","AnimationEffect","AnimationPlaybackEvent",
  "AnimationTimeline","Attr","AudioData","AudioDestinationNode","AudioListener","AudioNode","AudioParam","AudioParamMap",
  "AudioScheduledSourceNode","AudioWorklet","AudioWorkletNode","AuthenticatorAssertionResponse","AuthenticatorAttestationResponse",
  "AuthenticatorResponse","BackgroundFetchManager","BackgroundFetchRecord","BackgroundFetchRegistration","BarcodeDetector",
  "BaseAudioContext","BatteryManager","BeforeInstallPromptEvent","BiquadFilterNode","BlobEvent","BluetoothCharacteristicProperties",
  "BluetoothDevice","BluetoothRemoteGATTCharacteristic","BluetoothRemoteGATTDescriptor","BluetoothRemoteGATTServer","BluetoothRemoteGATTService",
  "BluetoothUUID","BrowserCaptureMediaStreamTrack","CDATASection","CSSAnimation","CSSConditionRule","CSSContainerRule","CSSCounterStyleRule",
  "CSSFontFaceRule","CSSFontFeatureValuesRule","CSSFontPaletteValuesRule","CSSGroupingRule","CSSImageValue","CSSImportRule","CSSKeyframeRule",
  "CSSKeyframesRule","CSSKeywordValue","CSSLayerBlockRule","CSSLayerStatementRule","CSSMathClamp","CSSMathInvert","CSSMathMax","CSSMathMin",
  "CSSMathNegate","CSSMathProduct","CSSMathSum","CSSMathValue","CSSMatrixComponent","CSSMediaRule","CSSNamespaceRule","CSSNumericArray",
  "CSSNumericValue","CSSPageRule","CSSPerspective","CSSPositionValue","CSSPropertyRule","CSSRotate","CSSRule","CSSRuleList","CSSScale",
  "CSSScopeRule","CSSSkew","CSSSkewX","CSSSkewY","CSSStartingStyleRule","CSSStyleDeclaration","CSSStyleRule","CSSStyleValue","CSSSupportsRule",
  "CSSTransformComponent","CSSTransformValue","CSSTransition","CSSTranslate","CSSUnitValue","CSSUnparsedValue","CSSVariableReferenceValue",
  "CanvasCaptureMediaStreamTrack","CanvasFilter","CanvasPattern","ChannelMergerNode","ChannelSplitterNode","CharacterBoundsUpdateEvent",
  "Clipboard","ClipboardEvent","ClipboardItem","ConstantSourceNode","ConvolverNode","CookieChangeEvent","CookieStore","CookieStoreManager",
  "CropTarget","CustomStateSet","DelayNode","DelegatedInkTrailPresenter","DeviceMotionEvent","DeviceMotionEventAcceleration",
  "DeviceMotionEventRotationRate","DeviceOrientationEvent","DocumentPictureInPicture","DocumentPictureInPictureEvent","DynamicsCompressorNode",
  "EditContext","EncodedAudioChunk","EncodedVideoChunk","EyeDropper","FeaturePolicy","FederatedCredential","Fence","FencedFrameConfig",
  "FetchLaterResult","FileSystemDirectoryHandle","FileSystemFileHandle","FileSystemHandle","FileSystemWritableFileStream","FontData",
  "FontFaceSet","FontFaceSetLoadEvent","FormDataEvent","FragmentDirective","GPUAdapter","GPUAdapterInfo","GPUBindGroup","GPUBindGroupLayout",
  "GPUBuffer","GPUBufferUsage","GPUCanvasContext","GPUColorWrite","GPUCommandBuffer","GPUCommandEncoder","GPUCompilationInfo","GPUCompilationMessage",
  "GPUComputePassEncoder","GPUComputePipeline","GPUDevice","GPUDeviceLostInfo","GPUError","GPUExternalTexture","GPUInternalError","GPUMapMode",
  "GPUOutOfMemoryError","GPUPipelineError","GPUPipelineLayout","GPUQuerySet","GPUQueue","GPURenderBundle","GPURenderBundleEncoder",
  "GPURenderPassEncoder","GPURenderPipeline","GPUSampler","GPUShaderModule","GPUShaderStage","GPUSupportedFeatures","GPUSupportedLimits",
  "GPUTexture","GPUTextureUsage","GPUTextureView","GPUUncapturedErrorEvent","GPUValidationError","GravitySensor","Gyroscope",
  "HID","HIDConnectionEvent","HIDDevice","HIDInputReportEvent","HTMLAllCollection","HTMLAnchorElement","HTMLAreaElement","HTMLAudioElement",
  "HTMLBRElement","HTMLBaseElement","HTMLBodyElement","HTMLButtonElement","HTMLCanvasElement","HTMLDListElement","HTMLDataElement",
  "HTMLDataListElement","HTMLDetailsElement","HTMLDialogElement","HTMLDirectoryElement","HTMLDivElement","HTMLDocument","HTMLEmbedElement",
  "HTMLFieldSetElement","HTMLFontElement","HTMLFormControlsCollection","HTMLFormElement","HTMLFrameElement","HTMLFrameSetElement",
  "HTMLHRElement","HTMLHeadElement","HTMLHeadingElement","HTMLHtmlElement","HTMLIFrameElement","HTMLImageElement","HTMLInputElement",
  "HTMLLIElement","HTMLLabelElement","HTMLLegendElement","HTMLLinkElement","HTMLMapElement","HTMLMarqueeElement","HTMLMediaElement",
  "HTMLMenuElement","HTMLMetaElement","HTMLMeterElement","HTMLModElement","HTMLOListElement","HTMLObjectElement","HTMLOptGroupElement",
  "HTMLOptionElement","HTMLOptionsCollection","HTMLOutputElement","HTMLParagraphElement","HTMLParamElement","HTMLPictureElement",
  "HTMLPreElement","HTMLProgressElement","HTMLQuoteElement","HTMLScriptElement","HTMLSelectElement","HTMLSlotElement","HTMLSourceElement",
  "HTMLSpanElement","HTMLStyleElement","HTMLTableCaptionElement","HTMLTableCellElement","HTMLTableColElement","HTMLTableElement",
  "HTMLTableRowElement","HTMLTableSectionElement","HTMLTemplateElement","HTMLTextAreaElement","HTMLTimeElement","HTMLTitleElement",
  "HTMLTrackElement","HTMLUListElement","HTMLUnknownElement","HTMLVideoElement","Highlight","HighlightRegistry","IIRFilterNode",
  "IdentityCredential","IdleDetector","ImageBitmapRenderingContext","ImageCapture","ImageTrack","ImageTrackList","Ink","InputDeviceInfo",
  "LargestContentfulPaint","LaunchParams","LaunchQueue","LayoutShift","LayoutShiftAttribution","LinearAccelerationSensor",
  "Lock","LockManager","MIDIAccess","MIDIConnectionEvent","MIDIInput","MIDIInputMap","MIDIMessageEvent","MIDIOutput","MIDIOutputMap",
  "MIDIPort","MediaCapabilities","MediaDeviceInfo","MediaElementAudioSourceNode","MediaEncryptedEvent","MediaError","MediaKeyMessageEvent",
  "MediaKeySession","MediaKeyStatusMap","MediaKeySystemAccess","MediaKeys","MediaList","MediaMetadata","MediaQueryList","MediaQueryListEvent",
  "MediaSession","MediaSource","MediaSourceHandle","MediaStreamAudioDestinationNode","MediaStreamAudioSourceNode","MediaStreamEvent",
  "MediaStreamTrack","MediaStreamTrackEvent","MediaStreamTrackGenerator","MediaStreamTrackProcessor","Navigation","NavigationCurrentEntryChangeEvent",
  "NavigationDestination","NavigationHistoryEntry","NavigationPrecommitController","NavigationTransition","NavigatorLogin","NavigatorManagedData",
  "NavigatorUAData","NetworkInformation","NotRestoredReasonDetails","NotRestoredReasons","OTPCredential","OfflineAudioCompletionEvent",
  "OrientationSensor","OverconstrainedError","PannerNode","PasswordCredential","PaymentAddress","PaymentManager","PaymentMethodChangeEvent",
  "PaymentRequest","PaymentRequestUpdateEvent","PaymentResponse","PerformanceElementTiming","PerformanceEventTiming","PerformanceLongAnimationFrameTiming",
  "PerformanceLongTaskTiming","PerformanceNavigationTiming","PerformancePaintTiming","PerformanceServerTiming","PeriodicSyncManager",
  "PeriodicWave","PermissionStatus","PictureInPictureEvent","PictureInPictureWindow","PlaybackSpeedChangeEvent","Plugin","PointerEvent",
  "Presentation","PresentationAvailability","PresentationConnection","PresentationConnectionAvailableEvent","PresentationConnectionCloseEvent",
  "PresentationConnectionList","PresentationReceiver","PresentationRequest","PressureObserver","PressureRecord","ProcessingInstruction",
  "Profiler","PromiseRejectionEvent","PushManager","PushSubscription","PushSubscriptionOptions","RTCCertificate","RTCDTMFSender",
  "RTCDTMFToneChangeEvent","RTCDataChannel","RTCDataChannelEvent","RTCDtlsTransport","RTCEncodedAudioFrame","RTCEncodedVideoFrame",
  "RTCError","RTCErrorEvent","RTCIceCandidate","RTCIceTransport","RTCPeerConnectionIceErrorEvent","RTCPeerConnectionIceEvent",
  "RTCRtpReceiver","RTCRtpSender","RTCRtpTransceiver","RTCSctpTransport","RTCSessionDescription","RTCStatsReport","RTCTrackEvent",
  "RadioNodeList","ReadableByteStreamController","ReadableStreamBYOBReader","ReadableStreamBYOBRequest","ReadableStreamDefaultController",
  "ReadableStreamDefaultReader","RelativeOrientationSensor","RemotePlayback","Request","ResizeObserverEntry","ResizeObserverSize",
  "RouterSourceEnum","SANDBOXED_FRAME","SVGAElement","SVGAngle","SVGAnimateElement","SVGAnimateMotionElement","SVGAnimateTransformElement",
  "SVGAnimatedAngle","SVGAnimatedBoolean","SVGAnimatedEnumeration","SVGAnimatedInteger","SVGAnimatedLength","SVGAnimatedLengthList",
  "SVGAnimatedNumber","SVGAnimatedNumberList","SVGAnimatedPreserveAspectRatio","SVGAnimatedRect","SVGAnimatedString","SVGAnimatedTransformList",
  "SVGAnimationElement","SVGCircleElement","SVGClipPathElement","SVGComponentTransferFunctionElement","SVGDefsElement","SVGDescElement",
  "SVGElement","SVGEllipseElement","SVGFEBlendElement","SVGFEColorMatrixElement","SVGFEComponentTransferElement","SVGFECompositeElement",
  "SVGFEConvolveMatrixElement","SVGFEDiffuseLightingElement","SVGFEDisplacementMapElement","SVGFEDistantLightElement","SVGFEDropShadowElement",
  "SVGFEFloodElement","SVGFEFuncAElement","SVGFEFuncBElement","SVGFEFuncGElement","SVGFEFuncRElement","SVGFEGaussianBlurElement",
  "SVGFEImageElement","SVGFEMergeElement","SVGFEMergeNodeElement","SVGFEMorphologyElement","SVGFEOffsetElement","SVGFEPointLightElement",
  "SVGFESpecularLightingElement","SVGFESpotLightElement","SVGFETileElement","SVGFETurbulenceElement","SVGFilterElement","SVGForeignObjectElement",
  "SVGGElement","SVGGeometryElement","SVGGradientElement","SVGGraphicsElement","SVGImageElement","SVGLength","SVGLengthList","SVGLineElement",
  "SVGLinearGradientElement","SVGMPathElement","SVGMarkerElement","SVGMaskElement","SVGMatrix","SVGMetadataElement","SVGNumber","SVGNumberList",
  "SVGPathElement","SVGPatternElement","SVGPoint","SVGPointList","SVGPolygonElement","SVGPolylineElement","SVGPreserveAspectRatio",
  "SVGRadialGradientElement","SVGRect","SVGRectElement","SVGSVGElement","SVGScriptElement","SVGSetElement","SVGStopElement","SVGStringList",
  "SVGStyleElement","SVGSwitchElement","SVGSymbolElement","SVGTSpanElement","SVGTextContentElement","SVGTextElement","SVGTextPathElement",
  "SVGTextPositioningElement","SVGTitleElement","SVGTransform","SVGTransformList","SVGUnitTypes","SVGUseElement","SVGViewElement",
  "Scheduler","Scheduling","ScreenDetailed","ScreenDetails","ScriptProcessorNode","ScrollTimeline","SecurityPolicyViolationEvent",
  "Selection","Sensor","SensorErrorEvent","Serial","SerialPort","SharedStorage","SharedStorageWorklet","SourceBuffer","SourceBufferList",
  "SpeechGrammar","SpeechGrammarList","SpeechRecognition","SpeechRecognitionErrorEvent","SpeechRecognitionEvent","SpeechSynthesis",
  "SpeechSynthesisErrorEvent","SpeechSynthesisEvent","SpeechSynthesisVoice","StaticRange","StereoPannerNode","StorageBucket",
  "StorageBucketManager","StorageManager","StylePropertyMap","StylePropertyMapReadOnly","StyleSheetList","SubtleCrypto","SyncManager",
  "TaskAttributionTiming","TaskController","TaskPriorityChangeEvent","TaskSignal","TextEvent","TextFormat","TextFormatUpdateEvent",
  "TextUpdateEvent","Timeline","ToggleEvent","Touch","TouchList","TrackEvent","TransformStreamDefaultController","TransitionEvent",
  "TrustedHTML","TrustedScript","TrustedScriptURL","TrustedTypePolicy","TrustedTypePolicyFactory","USB","USBAlternateInterface",
  "USBConfiguration","USBConnectionEvent","USBDevice","USBEndpoint","USBInTransferResult","USBInterface","USBIsochronousInTransferPacket",
  "USBIsochronousInTransferResult","USBIsochronousOutTransferPacket","USBIsochronousOutTransferResult","USBOutTransferResult",
  "UserActivation","VTTCue","VTTRegion","ValidityState","VideoColorSpace","VideoDecoder","VideoEncoder","VideoPlaybackQuality",
  "ViewTimeline","ViewTransition","ViewTransitionTypeSet","VirtualKeyboard","VirtualKeyboardGeometryChangeEvent","VisibilityStateEntry",
  "WGSLLanguageFeatures","WakeLock","WakeLockSentinel","WaveShaperNode","WebGL2RenderingContext","WebGLActiveInfo","WebGLBuffer",
  "WebGLContextEvent","WebGLFramebuffer","WebGLObject","WebGLProgram","WebGLQuery","WebGLRenderbuffer","WebGLSampler","WebGLShader",
  "WebGLShaderPrecisionFormat","WebGLSync","WebGLTexture","WebGLTransformFeedback","WebGLUniformLocation","WebGLVertexArrayObject",
  "WebKitMutationObserver","WebSocketError","WebSocketStream","WebTransport","WebTransportBidirectionalStream","WebTransportDatagramDuplexStream",
  "WebTransportError","WindowControlsOverlay","WindowControlsOverlayGeometryChangeEvent","WritableStreamDefaultController",
  "WritableStreamDefaultWriter","XMLHttpRequestEventTarget","XMLHttpRequestUpload",
];

function installChromeWindowSurface(windowLike) {
  const ctorNames = [
    "AggregateError", "Animation", "AnimationEvent", "Audio", "AudioBuffer", "AudioContext",
    "BarProp", "BeforeUnloadEvent", "Blob", "BlobEvent", "BroadcastChannel", "ByteLengthQueuingStrategy",
    "CSSStyleSheet", "Cache", "CacheStorage", "CanvasGradient", "CanvasRenderingContext2D",
    "CloseEvent", "Comment", "CompositionEvent", "CompressionStream", "CountQueuingStrategy",
    "Credential", "CredentialsContainer", "Crypto", "CryptoKey", "CustomElementRegistry",
    "DOMException", "DOMImplementation", "DOMMatrix", "DOMParser", "DOMPoint", "DOMQuad",
    "DOMRectReadOnly", "DOMStringList", "DOMTokenList", "DataTransfer", "DecompressionStream",
    "DocumentFragment", "DocumentTimeline", "DragEvent", "Element", "ErrorEvent", "EventSource",
    "EventTarget", "File", "FileList", "FileReader", "FocusEvent", "FontFace", "FormData",
    "GainNode", "Gamepad", "Geolocation", "HTMLCollection", "HashChangeEvent", "Headers",
    "History", "IDBFactory", "IdleDeadline", "Image", "ImageBitmap", "ImageData", "InputEvent",
    "IntersectionObserver", "KeyboardEvent", "MediaDevices", "MediaRecorder", "MediaStream",
    "MessageChannel", "MessagePort", "MimeTypeArray", "MouseEvent", "MutationObserver",
    "MutationRecord", "NamedNodeMap", "Navigator", "Node", "NodeList", "Notification",
    "OfflineAudioContext", "Option", "OscillatorNode", "PageTransitionEvent", "Path2D",
    "PerformanceEntry", "PerformanceMark", "PerformanceMeasure", "PerformanceNavigation",
    "PerformanceObserver", "PerformanceResourceTiming", "Permissions", "PluginArray",
    "PointerEvent", "PopStateEvent", "ProgressEvent", "PromiseRejectionEvent", "PublicKeyCredential",
    "RTCPeerConnection", "Range", "ReadableStream", "RemotePlayback", "Report", "ReportingObserver",
    "Request", "ResizeObserver", "Response", "Screen", "ScreenOrientation", "SecurityPolicyViolationEvent",
    "Selection", "ShadowRoot", "SharedWorker", "SpeechSynthesisUtterance", "Storage", "StorageEvent",
    "StyleSheet", "SubmitEvent", "SubtleCrypto", "Text", "TextDecoderStream", "TextEncoderStream",
    "TextMetrics", "TimeRanges", "TouchEvent", "TransformStream", "TransitionEvent", "TreeWalker",
    "UIEvent", "URLPattern", "UserActivation", "ValidityState", "VideoFrame", "VisualViewport",
    "WebGLRenderingContext", "WebSocket", "WheelEvent", "Window", "Worker", "Worklet",
    "WritableStream", "XMLDocument", "XMLHttpRequest", "XMLSerializer", "XPathEvaluator", "XSLTProcessor",
  ];
  const names = [...new Set([...ctorNames, ...CHROME_WINDOW_PROP_NAMES])];
  for (const name of names) {
    if (windowLike[name]) continue;
    windowLike[name] = makeNativeFunction(name, function ChromeCtor() { return {}; });
  }
  const fnNames = [
    "alert", "confirm", "prompt", "open", "close", "print", "stop", "focus", "blur",
    "getSelection", "find", "scroll", "moveTo", "moveBy", "resizeTo", "resizeBy",
    "structuredClone", "reportError", "createImageBitmap", "getComputedStyle",
    "matchMedia", "requestAnimationFrame", "cancelAnimationFrame",
  ];
  for (const name of fnNames) {
    if (typeof windowLike[name] === "function") continue;
    windowLike[name] = makeNativeFunction(name);
  }
}

// seedSessionObserverTelemetry 产出的遥测键值；sdk.js 会在初始化后清掉其中一部分，
// 因此每次执行 DX 前用这份原始值写回（见 reapplySessionObserverTelemetry）。
let sessionObserverTelemetry = null;

function reapplySessionObserverTelemetry(windowLike) {
  if (!windowLike || !sessionObserverTelemetry) return 0;
  let restored = 0;
  try {
    for (const [name, value] of Object.entries(sessionObserverTelemetry)) {
      if (windowLike[name] === undefined) {
        windowLike[name] = value;
        restored += 1;
      }
    }
  } catch {}
  if (restored) soDxLog(`telemetry restored ${restored} keys before DX`);
  return restored;
}

function seedSessionObserverTelemetry(windowLike, options) {
  const nowP = Number(windowLike?.performance?.now?.() || 1500);
  const t0 = nowP - 8085.5;
  const keys = ["A", "n", "n", "a", " ", "W", "i", "l", "s", "o", "n", "2", "t", "e", "s", "t", "1", "2", "3", "Enter"];
  const kd = [];
  let kt = t0 + 1200;
  for (let i = 0; i < keys.length; i++) {
    kt += 140 + Math.random() * 90;
    kd.push({
      ctrlKey: false,
      metaKey: false,
      altKey: false,
      shiftKey: i === 0 || i === 5,
      key: keys[i],
      type: "keydown",
      t: kt,
    });
    kd.push({
      ctrlKey: false,
      metaKey: false,
      altKey: false,
      shiftKey: i === 0 || i === 5,
      key: keys[i],
      type: "keyup",
      t: kt + 70 + Math.random() * 40,
    });
  }
  const pm = [];
  let px = Math.max(240, Math.floor((options?.screen?.width || 1440) / 2));
  let py = Math.max(180, Math.floor((options?.screen?.height || 900) / 2));
  let pt = t0 + 300;
  let htot = 0;
  let pcnt = 0;
  for (let j = 0; j < 260; j++) {
    const dx = (Math.random() - 0.5) * 28;
    const dy = (Math.random() - 0.5) * 22;
    px += dx;
    py += dy;
    pt += 45 + Math.random() * 55;
    htot += Math.hypot(dx, dy);
    pcnt += 1;
    pm.push({ clientX: Math.round(px), clientY: Math.round(py), type: "pointermove", t: pt });
  }
  const telemetry = {
    __oai_so_t0: t0,
    __oai_so_h: kd,
    __oai_so_hi: kd.length,
    __oai_so_hp: 2,
    __oai_so_hw: 1,
    __oai_so_s: 3,
    __oai_so_k: keys.length,
    __oai_so_kp: keys.length,
    __oai_so_we: 1,
    __oai_so_wb: 0,
    __oai_so_wl: 1,
    __oai_so_fs: 1,
    __oai_so_fs2: 1,
    __oai_so_fn: 0,
    __oai_so_p: pm,
    __oai_so_pc: pcnt,
    __oai_so_i: [
      { type: "pointerdown", clientX: Math.round(px), clientY: Math.round(py), t: pt + 80 },
      { type: "pointerup", clientX: Math.round(px), clientY: Math.round(py), t: pt + 132 },
      { type: "click", clientX: Math.round(px), clientY: Math.round(py), t: pt + 168 },
      { type: "scroll", clientX: Math.round(px), clientY: Math.round(py), t: pt + 240 },
    ],
    // snapshot_dx 会读这三个；之前没定义，序列化时被整段跳过（so 卡在 ~565）。
    __oai_so_uk: [...new Set(keys)],
    __oai_so_uin: keys.length,
    __oai_so_ui: [
      { type: "input", value: "An", t: kd[0]?.t ?? t0 + 1440 },
      { type: "input", value: "Anna Wilson2", t: kd[kd.length - 1]?.t ?? t0 + 3200 },
      { type: "change", value: "Anna Wilson2", t: (kd[kd.length - 1]?.t ?? t0 + 3200) + 90 },
    ],
    __oai_so_m: pm.length,
    __oai_so_ht: htot,
    __oai_so_hc: pcnt,
    __oai_so_bc: 4,
    __oai_so_bm: 1,
    __oai_so_ss: 1,
    __oai_so_ss2: 1,
    __oai_so_sn: 1,
    __oai_so_cs: 1,
    __oai_so_cs2: 1,
    __oai_so_cn: 4,
    __oai_so_st: 1,
    __oai_so_sw: 120,
    __oai_so_sp: 1,
    __oai_so_spt: 2,
    __oai_so_sx0: Math.round(px),
    __oai_so_sy0: Math.round(py),
    __oai_so_lx: Math.round(px),
    __oai_so_ly: Math.round(py),
  };
  Object.assign(windowLike, telemetry);
  // sdk.js 加载后会把其中若干键清成 undefined（实测 __oai_so_wl / __oai_so_m），
  // 之后 DX 执行时读到 undefined 就整段跳过，so/t 载荷因此比真浏览器薄。
  // 这里留一份原始值，供每次执行 DX 前重新写回。
  sessionObserverTelemetry = telemetry;
  return telemetry;
}

// 真浏览器（auth.openai.com/email-verification）的环境面快照，由 tools 侧抓取后落到
// sentinel/env-surface.json。目前用于 performance 条目回放：turnstile DX 会数
// performance 条目判断"页面是否已充分加载"，条目少就提前结束 trace（t 停在 ~1030）。
let envSurfaceCache = null;

function loadEnvSurface() {
  if (envSurfaceCache !== null) return envSurfaceCache;
  try {
    const surfacePath = path.resolve(__dirname, "env-surface.json");
    envSurfaceCache = JSON.parse(fs.readFileSync(surfacePath, "utf8"));
  } catch (error) {
    soDxLog("env-surface.json 读取失败，退回合成条目：" + (error && error.message || error));
    envSurfaceCache = {};
  }
  return envSurfaceCache;
}

function createIntlObject(options) {
  const intlObject = Object.create(Intl);
  const NativeDateTimeFormat = Intl.DateTimeFormat;
  // 真 Chrome 会**规范化** IANA 名：传 Asia/Ho_Chi_Minh 报 Asia/Saigon，
  // 传 Asia/Kolkata 报 Asia/Calcutta（Chromium 148 + 系统 Chrome 153 实测一致）。
  // 旧代码直接把 options.timeZone 原样回填，等于漏了这一步 —— 和真浏览器对不上。
  const tzCanonical = tzProfile.computeTzProfile(options).canonical;
  function DateTimeFormatMock(locales, formatOptions = {}) {
    const mergedOptions = { ...(formatOptions || {}) };
    if (options.timeZone) mergedOptions.timeZone = options.timeZone;
    const fmt = new NativeDateTimeFormat(locales || options.languages || options.language, mergedOptions);
    const nativeResolvedOptions = fmt.resolvedOptions.bind(fmt);
    Object.defineProperty(fmt, "resolvedOptions", {
      value: () => {
        const resolved = nativeResolvedOptions();
        if (options.timeZone) resolved.timeZone = tzCanonical;
        if (options.language) resolved.locale = options.language;
        return resolved;
      },
    });
    return fmt;
  }
  DateTimeFormatMock.prototype = NativeDateTimeFormat.prototype;
  Object.setPrototypeOf(DateTimeFormatMock, NativeDateTimeFormat);
  intlObject.DateTimeFormat = DateTimeFormatMock;
  return intlObject;
}

function createPerformanceObserver(observerSet) {
  return class PerformanceObserverMock {
    constructor(callback) { this.callback = callback; this._observed = false; this._types = new Set(); }
    observe(options = {}) {
      this._observed = true;
      if (options.type) this._types.add(String(options.type));
      if (Array.isArray(options.entryTypes)) for (const type of options.entryTypes) this._types.add(String(type));
      observerSet.add(this);
    }
    disconnect() { this._observed = false; observerSet.delete(this); }
    takeRecords() { return []; }
    _notify(entry) {
      if (!this._observed) return;
      if (this._types.size && !this._types.has(entry.entryType)) return;
      try { this.callback({ getEntries: () => [entry], getEntriesByType: (type) => entry.entryType === String(type) ? [entry] : [] }); } catch {}
    }
    static get supportedEntryTypes() { return ["navigation", "resource", "paint", "mark", "measure"]; }
  };
}

function createNetworkInformation() {
  const target = createEventTarget();
  const info = {
    downlink: 10,
    effectiveType: "4g",
    rtt: 50,
    saveData: false,
    type: "wifi",
    onchange: null,
    addEventListener: target.addEventListener,
    removeEventListener: target.removeEventListener,
    dispatchEvent: target.dispatchEvent,
  };
  Object.defineProperty(info, Symbol.toStringTag, { value: "NetworkInformation" });
  return info;
}

function createCookieJar(initialCookie = "") {
  const values = new Map();
  for (const part of String(initialCookie || "").split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf("=");
    if (idx <= 0) continue;
    values.set(trimmed.slice(0, idx), trimmed.slice(idx + 1));
  }
  return {
    get cookie() {
      return [...values.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    },
    set cookie(value) {
      const first = String(value || "").split(";")[0];
      const idx = first.indexOf("=");
      if (idx > 0) values.set(first.slice(0, idx).trim(), first.slice(idx + 1).trim());
    },
  };
}

function makeNativeFunction(name, impl = () => undefined) {
  const fn = function (...args) { return impl.apply(this, args); };
  Object.defineProperty(fn, "name", { value: name });
  Object.defineProperty(fn, "toString", { value: () => `function ${name}() { [native code] }` });
  return fn;
}

function createPluginArray(isSafari = false) {
  const makePlugin = (name) => ({
    name,
    filename: "internal-pdf-viewer",
    description: "Portable Document Format",
    length: 2,
    item(index) { return this[index] || null; },
    namedItem(type) { return this[type] || null; },
  });
  const pdf = { type: "application/pdf", suffixes: "pdf", description: "Portable Document Format", enabledPlugin: null };
  const textPdf = { type: "text/pdf", suffixes: "pdf", description: "Portable Document Format", enabledPlugin: null };
  const plugins = isSafari ? [
    makePlugin("WebKit built-in PDF"),
    makePlugin("PDF Viewer"),
  ] : [
    makePlugin("PDF Viewer"),
    makePlugin("Chrome PDF Viewer"),
    makePlugin("Chromium PDF Viewer"),
    makePlugin("Microsoft Edge PDF Viewer"),
    makePlugin("WebKit built-in PDF"),
  ];
  for (const plugin of plugins) {
    plugin[0] = pdf;
    plugin[1] = textPdf;
    plugin["application/pdf"] = pdf;
    plugin["text/pdf"] = textPdf;
  }
  pdf.enabledPlugin = plugins[0];
  textPdf.enabledPlugin = plugins[0];
  plugins.item = (index) => plugins[index] || null;
  plugins.namedItem = (name) => plugins.find((p) => p.name === name) || null;
  plugins.refresh = () => undefined;
  Object.defineProperty(plugins, Symbol.toStringTag, { value: "PluginArray" });
  return plugins;
}

function createMimeTypeArray() {
  const plugin = { name: "PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" };
  const mimes = [
    { type: "application/pdf", suffixes: "pdf", description: "Portable Document Format", enabledPlugin: plugin },
    { type: "text/pdf", suffixes: "pdf", description: "Portable Document Format", enabledPlugin: plugin },
  ];
  mimes.item = (index) => mimes[index] || null;
  mimes.namedItem = (type) => mimes.find((m) => m.type === type) || null;
  Object.defineProperty(mimes, Symbol.toStringTag, { value: "MimeTypeArray" });
  return mimes;
}

function createCanvas(width = 300, height = 150, isSafari = false) {
  const canvas = {
    tagName: "CANVAS",
    style: {},
    width,
    height,
    parentNode: null,
    getBoundingClientRect() { return createDomRect(this.width, this.height); },
    toDataURL() { return "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAFgwJ/lxv8dQAAAABJRU5ErkJggg=="; },
    getContext(type) {
      const name = String(type || "").toLowerCase();
      if (name === "2d") {
        return {
          canvas,
          fillStyle: "#000000",
          strokeStyle: "#000000",
          font: "10px sans-serif",
          fillRect() {}, clearRect() {}, strokeRect() {}, beginPath() {}, closePath() {}, moveTo() {}, lineTo() {}, stroke() {}, fill() {},
          fillText() {}, strokeText() {}, measureText(text) { return { width: String(text || "").length * 6.5 }; },
          getImageData() { return { data: new Uint8ClampedArray(canvas.width * canvas.height * 4), width: canvas.width, height: canvas.height }; },
          putImageData() {}, createImageData(w, h) { return { data: new Uint8ClampedArray(w * h * 4), width: w, height: h }; },
        };
      }
      if (name === "webgl" || name === "experimental-webgl" || name === "webgl2") {
        return {
          canvas,
          getParameter(param) {
            const values = new Map([
              [0x1f00, "WebKit"],                    // VENDOR
              [0x1f01, "WebKit WebGL"],              // RENDERER
              [0x1f02, isSafari ? "WebGL 2.0" : "WebGL 2.0 (OpenGL ES 3.0 Chromium)"],
              [0x8b8c, isSafari ? "WebGL GLSL ES 1.0" : "WebGL GLSL ES 3.00 (OpenGL ES GLSL ES 3.0 Chromium)"],
              [0x0d33, 16384],                       // MAX_TEXTURE_SIZE
              [0x8869, 16],                          // MAX_VERTEX_ATTRIBS
            ]);
            return values.has(param) ? values.get(param) : 0;
          },
          getExtension(name) {
            if (name === "WEBGL_debug_renderer_info") {
              return { UNMASKED_VENDOR_WEBGL: 0x9245, UNMASKED_RENDERER_WEBGL: 0x9246 };
            }
            return {};
          },
          getSupportedExtensions() { return ["ANGLE_instanced_arrays", "EXT_blend_minmax", "WEBGL_debug_renderer_info", "WEBGL_lose_context"]; },
          clearColor() {}, clear() {}, viewport() {}, createBuffer() { return {}; }, bindBuffer() {}, bufferData() {},
        };
      }
      return null;
    },
    addEventListener() {}, removeEventListener() {},
  };
  return canvas;
}

function createAudioContext() {
  return class AudioContextMock {
    constructor() { this.sampleRate = 48000; this.state = "running"; this.destination = {}; }
    createOscillator() { return { type: "sine", frequency: { value: 440 }, connect() {}, start() {}, stop() {} }; }
    createAnalyser() { return { fftSize: 2048, frequencyBinCount: 1024, getFloatFrequencyData() {}, getByteFrequencyData() {} }; }
    createGain() { return { gain: { value: 1 }, connect() {} }; }
    close() { this.state = "closed"; return Promise.resolve(); }
    resume() { this.state = "running"; return Promise.resolve(); }
    suspend() { this.state = "suspended"; return Promise.resolve(); }
  };
}

function createBrowserContext(options) {
  const windowTarget = createEventTarget();
  const managedTimers = new Set();
  const managedSetTimeout = (callback, delay, ...args) => {
    const id = setTimeout(() => {
      managedTimers.delete(id);
      callback(...args);
    }, delay);
    managedTimers.add(id);
    return id;
  };
  const managedClearTimeout = (id) => {
    managedTimers.delete(id);
    clearTimeout(id);
  };
  const forcedRandomUUID = options.sentinelSid || "";
  let randomUUIDCalls = 0;
  const browserCrypto = Object.create(crypto.webcrypto);
  browserCrypto.randomUUID = () => {
    randomUUIDCalls += 1;
    // 当前 sdk.js 的第一次 UUID 调用用于 Sentinel 内部 sid。
    // 只固定这一次，避免后续 UUID 全部重复。
    if (forcedRandomUUID && randomUUIDCalls === 1) return forcedRandomUUID;
    return crypto.randomUUID();
  };
  browserCrypto.getRandomValues = crypto.webcrypto.getRandomValues.bind(crypto.webcrypto);

  const performanceObservers = new Set();
  const perfEntries = [{
    name: options.pageUrl,
    entryType: "navigation",
    startTime: 0,
    duration: Math.max(1, performance.now()),
    initiatorType: "navigation",
    nextHopProtocol: options.nextHopProtocol || "h2",
    transferSize: 0,
    encodedBodySize: 0,
    decodedBodySize: 0,
    toJSON() { return { ...this }; },
  }];
  // 真机首次加载 chatgpt.com 会有几十条 resource 条目；只有 1 条会让 DX 判定成
  // "刚打开的空白页"，提前结束 trace（t 停在 ~1030，HAR 1816）。
  const seededResourceUrls = [
    "https://chatgpt.com/cdn-cgi/challenge-platform/scripts/jsd/api.js?onload=jsdOnload",
    "https://sentinel.openai.com/backend-api/sentinel/sdk.js",
    "https://sentinel.openai.com/sentinel/20260810913b/sdk.js",
    "https://chatgpt.com/_next/static/chunks/webpack.js",
    "https://chatgpt.com/_next/static/chunks/main-app.js",
    "https://chatgpt.com/_next/static/chunks/framework.js",
    "https://chatgpt.com/_next/static/css/app.css",
    "https://chatgpt.com/backend-api/sentinel/chat-requirements/prepare",
    "https://chatgpt.com/api/auth/session",
    "https://accounts.google.com/gsi/client",
    "https://js.stripe.com/v3/",
    "https://chatgpt.com/backend-api/me",
  ];
  const envSurface = loadEnvSurface();
  const capturedEntries = Array.isArray(envSurface.perfEntries) ? envSurface.perfEntries : [];
  const capturedResources = capturedEntries.filter((entry) => entry && entry.entryType !== "navigation");
  if (capturedResources.length >= 20) {
    // 用真机快照回放：名称、时序、体积全按真值，只加毫秒级抖动避免每个号时间线逐毫秒一致。
    const navCaptured = capturedEntries.find((entry) => entry && entry.entryType === "navigation");
    if (navCaptured && Number.isFinite(Number(navCaptured.duration))) {
      perfEntries[0].duration = Number(navCaptured.duration);
      if (Number.isFinite(Number(navCaptured.decodedBodySize))) perfEntries[0].decodedBodySize = Number(navCaptured.decodedBodySize);
      if (Number.isFinite(Number(navCaptured.transferSize))) perfEntries[0].transferSize = Number(navCaptured.transferSize);
    }
    for (const src of capturedResources) {
      const entry = { ...src };
      entry.startTime = Math.max(0, Number(entry.startTime) || 0) + Math.random() * 4;
      entry.nextHopProtocol = entry.nextHopProtocol || options.nextHopProtocol || "h2";
      entry.toJSON = function toJSON() { return { ...this }; };
      perfEntries.push(entry);
    }
    soDxLog("perf 条目已用真机快照回放 total=" + perfEntries.length + " (captured=" + capturedResources.length + ")");
  } else {
    let seededAt = 280;
    for (const url of seededResourceUrls) {
      seededAt += 137 + Math.random() * 320;
      perfEntries.push({
        name: url,
        entryType: "resource",
        initiatorType: url.endsWith(".css") ? "link" : (url.includes("_next") ? "script" : "fetch"),
        startTime: seededAt,
        requestStart: seededAt + 1,
        responseStart: seededAt + 12,
        responseEnd: seededAt + 48,
        duration: 48,
        transferSize: 1024,
        encodedBodySize: 980,
        decodedBodySize: 2400,
        nextHopProtocol: options.nextHopProtocol || "h2",
        toJSON() { return { ...this }; },
      });
    }
    soDxLog("perf 条目走合成种子 total=" + perfEntries.length);
  }
  function pushPerformanceEntry(entry) {
    perfEntries.push(entry);
    for (const observer of [...performanceObservers]) observer._notify?.(entry);
  }

  applyDateTimezone(Date, options);
  // node 在 Windows 上的默认 locale 是**系统 locale**（本机 zh-CN），且 LC_ALL/LANG/
  // --icu-locale 都改不动它。于是 vm 里任何不显式传 locale 的调用都会吐中文格式：
  //   new Date().toLocaleString() -> "2026/9/22 21:38:41"   ← zh-CN 顺序
  // 真浏览器在 navigator.language=vi-VN 下是 "21:38:41 22/9/2026"。这里绑死到页面 locale。
  if (process.env.SENTINEL_LOCALE_PATCH !== "0") {
    tzProfile.applyLocaleDefaults(globalThis, options);
  }
  const browserIntl = createIntlObject(options);

  const pageAgeMs = 27894.9;
  const browserPerformance = {
    now: () => pageAgeMs + performance.now(),
    timeOrigin: Date.now() - pageAgeMs,
    memory: {
      jsHeapSizeLimit: options.jsHeapSizeLimit,
      totalJSHeapSize: Math.floor(options.jsHeapSizeLimit / 3),
      usedJSHeapSize: Math.floor(options.jsHeapSizeLimit / 8),
    },
    getEntries() { return perfEntries.slice(); },
    getEntriesByType(type) { return perfEntries.filter((entry) => entry.entryType === String(type)); },
    getEntriesByName(name) { return perfEntries.filter((entry) => entry.name === String(name)); },
    mark(name) { pushPerformanceEntry({ name: String(name), entryType: "mark", startTime: this.now(), duration: 0, toJSON() { return { ...this }; } }); },
    measure(name) { pushPerformanceEntry({ name: String(name), entryType: "measure", startTime: this.now(), duration: 0, toJSON() { return { ...this }; } }); },
    clearMarks() {},
    clearMeasures() {},
  };
  const mathObject = Object.create(Math);
  if (Number.isFinite(options.fixedRandom)) {
    mathObject.random = () => options.fixedRandom;
  }
  const currentScript = { src: options.scriptSrc, length: options.scriptSrc.length };
  const appBuildPath = options.buildId && String(options.buildId).startsWith("c/")
    ? String(options.buildId)
    : `c/${options.buildId || FALLBACK_BUILD_ID}/_/`;
  const appScriptSrc = `https://chatgpt.com/${appBuildPath}ssg.js`;
  const scripts = [
    currentScript,
    { src: "https://accounts.google.com/gsi/client", length: 38 },
    { src: "https://chatgpt.com/cdn-cgi/challenge-platform/scripts/jsd/api.js?onload=jsdOnload", length: 84 },
    { src: appScriptSrc, length: appScriptSrc.length },
    { src: "https://chatgpt.com/_next/static/chunks/webpack.js", length: 48 },
    { src: "https://js.stripe.com/v3/", length: 24 },
  ];
  const attrs = new Map();
  if (options.buildId) attrs.set("data-build", options.buildId);
  const reactListeningKey = options.reactListeningKey || "_reactListening" + crypto.randomBytes(6).toString("hex");
  const reactContainerKey = options.reactContainerKey || "__reactContainer$" + crypto.randomBytes(6).toString("hex");
  const reactResourcesKey = options.reactResourcesKey || reactContainerKey.replace("__reactContainer$", "__reactResources$");

  const cookieJar = createCookieJar(options.cookie);
  const location = new URL(options.pageUrl);
  let iframeNode = null;
  const bodyChildren = [];
  const documentTarget = createEventTarget();
  const document = {
    currentScript,
    scripts,
    get cookie() { return cookieJar.cookie; },
    set cookie(value) { cookieJar.cookie = value; },
    URL: options.pageUrl,
    documentURI: options.pageUrl,
    referrer: options.referrer || "https://auth.openai.com/",
    title: "",
    origin: location.origin,
    location,
    characterSet: "UTF-8",
    charset: "UTF-8",
    compatMode: "CSS1Compat",
    contentType: "text/html",
    readyState: "complete",
    visibilityState: "visible",
    hidden: false,
    wasDiscarded: false,
    prerendering: false,
    fullscreenEnabled: true,
    fullscreenElement: null,
    pointerLockElement: null,
    scrollingElement: null,
    activeElement: null,
    adoptedStyleSheets: [],
    fonts: { ready: Promise.resolve(), check() { return true; }, load: async () => [] },
    timeline: { currentTime: 0 },
    pictureInPictureEnabled: true,
    alinkColor: "",
    bgColor: "",
    fgColor: "",
    linkColor: "",
    vlinkColor: "",
    anchors: [],
    applets: [],
    images: [],
    links: [],
    embeds: [],
    forms: [],
    plugins: [],
    all: { length: 0, item() { return null; }, namedItem() { return null; } },
    children: [],
    childElementCount: 2,
    firstElementChild: null,
    lastElementChild: null,
    firstChild: null,
    lastChild: null,
    nextSibling: null,
    previousSibling: null,
    parentNode: null,
    parentElement: null,
    ownerDocument: null,
    nodeType: 9,
    nodeName: "#document",
    nodeValue: null,
    baseURI: options.pageUrl,
    isConnected: true,
    dir: "ltr",
    designMode: "off",
    domain: location.hostname,
    lastModified: new Date().toString(),
    readyState: "complete",
    referrer: options.referrer || "https://chatgpt.com/",
    selectedStyleSheetSet: null,
    lastStyleSheetSet: null,
    preferredStyleSheetSet: "",
    styleSheetSets: [],
    xmlEncoding: null,
    xmlStandalone: false,
    xmlVersion: null,
    onfullscreenchange: null,
    onfullscreenerror: null,
    onpointerlockchange: null,
    onpointerlockerror: null,
    onreadystatechange: null,
    onselectionchange: null,
    onvisibilitychange: null,
    oncopy: null,
    oncut: null,
    onpaste: null,
    onabort: null,
    onauxclick: null,
    onbeforeinput: null,
    onbeforetoggle: null,
    onblur: null,
    onclick: null,
    onclose: null,
    oncontextmenu: null,
    ondblclick: null,
    onerror: null,
    onfocus: null,
    oninput: null,
    onkeydown: null,
    onkeyup: null,
    onload: null,
    onmousedown: null,
    onmousemove: null,
    onmouseout: null,
    onmouseover: null,
    onmouseup: null,
    onpointerdown: null,
    onpointermove: null,
    onpointerup: null,
    onscroll: null,
    onscrollend: null,
    onsubmit: null,
    onwheel: null,
    hasFocus() { return true; },
    [reactListeningKey]: true,
    [reactContainerKey]: true,
    [reactResourcesKey]: true,
    defaultView: null,
    head: null,
    documentElement: {
      nodeType: 1,
      nodeName: "HTML",
      tagName: "HTML",
      ownerDocument: null,
      style: createStyleDeclaration(),
      clientWidth: options.screen.width,
      clientHeight: options.screen.height,
      scrollWidth: options.screen.width,
      scrollHeight: options.screen.height,
      getAttribute(name) {
        return attrs.get(name) ?? null;
      },
      setAttribute(name, value) {
        attrs.set(name, String(value));
      },
      querySelector() { return null; },
      querySelectorAll() { return []; },
      getBoundingClientRect() {
        return createDomRect(options.screen.width, options.screen.height);
      },
    },
    body: {
      nodeType: 1,
      nodeName: "BODY",
      tagName: "BODY",
      ownerDocument: null,
      parentNode: null,
      parentElement: null,
      children: bodyChildren,
      childNodes: bodyChildren,
      style: createStyleDeclaration(),
      clientWidth: options.screen.width,
      clientHeight: options.screen.height,
      getBoundingClientRect() {
        return createDomRect(options.screen.width, options.screen.height);
      },
      appendChild(node) {
        bodyChildren.push(node);
        node.parentNode = document.body;
        if (node?.tagName === "IFRAME") iframeNode = node;
        managedSetTimeout(() => node?._emitLoad?.(), 0);
        return node;
      },
      removeChild(node) {
        const index = bodyChildren.indexOf(node);
        if (index >= 0) bodyChildren.splice(index, 1);
        if (iframeNode === node) iframeNode = null;
        if (node) node.parentNode = null;
        return node;
      },
    },
    addEventListener: documentTarget.addEventListener,
    removeEventListener: documentTarget.removeEventListener,
    dispatchEvent: documentTarget.dispatchEvent,
    querySelector(selector) {
      const q = String(selector || "").toLowerCase();
      if (q === "head") return this.head;
      if (q === "body") return this.body;
      if (q === "html" || q === "documentelement") return this.documentElement;
      return null;
    },
    querySelectorAll(selector) { const item = this.querySelector(selector); return item ? [item] : []; },
    getElementById() { return null; },
    getElementsByTagName(name) {
      const n = String(name).toLowerCase();
      if (n === "script") return scripts;
      if (n === "head") return [this.head];
      if (n === "body") return [this.body];
      if (n === "html") return [this.documentElement];
      return [];
    },
    createTextNode(text) { return { nodeType: 3, nodeName: "#text", textContent: String(text || ""), parentNode: null, ownerDocument: document }; },
    createElement(tagName) {
      const lowerTag = String(tagName).toLowerCase();
      if (lowerTag === "canvas") {
        const canvas = createCanvas(300, 150, isSafari);
        canvas.ownerDocument = document;
        return canvas;
      }
      if (lowerTag !== "iframe") {
        return createElementNode(tagName, document);
      }

      const target = createEventTarget();
      const iframe = createElementNode("iframe", document);
      Object.assign(iframe, {
        src: "",
        width: "",
        height: "",
        sandbox: { value: "", toString() { return this.value; } },
        getBoundingClientRect() {
          return createDomRect();
        },
        contentWindow: {
          postMessage(message, origin) {
            Promise.resolve()
              .then(async () => {
                const result = await options.handleIframeMessage(message);
                windowTarget.dispatchEvent({
                  type: "message",
                  source: iframe.contentWindow,
                  origin,
                  data: {
                    type: "response",
                    requestId: message.requestId,
                    result,
                  },
                });
              })
              .catch((error) => {
                windowTarget.dispatchEvent({
                  type: "message",
                  source: iframe.contentWindow,
                  origin,
                  data: {
                    type: "response",
                    requestId: message.requestId,
                    error: error?.message || String(error),
                  },
                });
              });
          },
        },
        addEventListener: target.addEventListener,
        removeEventListener: target.removeEventListener,
        dispatchEvent: target.dispatchEvent,
        _emitLoad() {
          target.dispatchEvent.call(iframe, { type: "load", target: iframe });
        },
      });
      return iframe;
    },
  };

  document.defaultView = null;
  document.documentElement.ownerDocument = document;
  document.body.ownerDocument = document;
  document.head = createElementNode("head", document);

  const browserFamily = String(options.browserFamily || "chrome").toLowerCase();
  const isSafari = browserFamily === "safari" || /Version\/[^ ]+ Safari\//.test(String(options.userAgent || ""));
  const exposeRequestIdleCallback = !isSafari && options.requestIdleCallback !== false;
  const credentialsContainer = {
    get: makeNativeFunction("get"),
    store: makeNativeFunction("store"),
    create: makeNativeFunction("create"),
    preventSilentAccess: makeNativeFunction("preventSilentAccess"),
    toString() { return "[object CredentialsContainer]"; },
  };
  Object.defineProperty(credentialsContainer, Symbol.toStringTag, { value: "CredentialsContainer" });
  const navigatorProto = isSafari ? {
    javaEnabled: makeNativeFunction("javaEnabled", () => false),
    sendBeacon: makeNativeFunction("sendBeacon", () => true),
    getGamepads: makeNativeFunction("getGamepads", () => []),
    webkitGetUserMedia: makeNativeFunction("webkitGetUserMedia"),
  } : {
    createAuctionNonce: makeNativeFunction("createAuctionNonce", () => crypto.randomUUID()),
    clearOriginJoinedAdInterestGroups: makeNativeFunction("clearOriginJoinedAdInterestGroups"),
    updateAdInterestGroups: makeNativeFunction("updateAdInterestGroups"),
    canLoadAdAuctionFencedFrame: makeNativeFunction("canLoadAdAuctionFencedFrame", () => false),
    registerProtocolHandler: makeNativeFunction("registerProtocolHandler"),
    deprecatedReplaceInURN: makeNativeFunction("deprecatedReplaceInURN"),
    getBattery: makeNativeFunction("getBattery", () => Promise.resolve({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: 1 })),
    getGamepads: makeNativeFunction("getGamepads", () => []),
    javaEnabled: makeNativeFunction("javaEnabled", () => false),
    sendBeacon: makeNativeFunction("sendBeacon", () => true),
    vibrate: makeNativeFunction("vibrate", () => false),
    // HAR p[10] 来自 Object.keys(Object.getPrototypeOf(navigator))。
    // doNotTrack 在真机原型上，toString 会抛，SDK catch 后只留下键名。
    doNotTrack: null,
    credentials: credentialsContainer,
  };
  const navigator = Object.create(navigatorProto);
  Object.assign(navigator, {
    userAgent: options.userAgent,
    language: options.language,
    languages: options.languages,
    cookieEnabled: true,
    onLine: true,
    pdfViewerEnabled: true,
    plugins: createPluginArray(isSafari),
    mimeTypes: createMimeTypeArray(),
    hardwareConcurrency: options.hardwareConcurrency,
    // navigator.deviceMemory 只可能是 0.25/0.5/1/2/4/8，超过 8 是物理不可能值。
    ...(isSafari ? {} : { deviceMemory: Math.min(8, Number(options.deviceMemory) || 8) }),
    maxTouchPoints: 0,
    platform: options.navigatorPlatform || "Win32",
    vendor: options.navigatorVendor || (isSafari ? "Apple Computer, Inc." : "Google Inc."),
    webdriver: false,
    bluetooth: { toString: () => "[object Bluetooth]" },
    ...(isSafari ? {} : { gpu: { toString: () => "[object GPU]" } }),
    connection: createNetworkInformation(),
    permissions: { query: async () => ({ state: "prompt", onchange: null }) },
    geolocation: {
      getCurrentPosition(success, error) { if (typeof error === "function") error({ code: 1, message: "User denied Geolocation" }); },
      watchPosition() { return 1; },
      clearWatch() {},
    },
    mediaDevices: {
      enumerateDevices: async () => [],
      getUserMedia: async () => { throw new Error("Permission denied"); },
    },
    storage: { estimate: async () => ({ quota: 10737418240, usage: 0 }) },
    ...(isSafari ? {} : {
      login: { toString: () => "[object NavigatorLogin]" },
      presentation: { toString: () => "[object Presentation]" },
      userAgentData: {
        mobile: false,
        platform: options.userAgentDataPlatform || options.secChUaPlatform || "Windows",
        brands: parseSecChBrands(options.secChUa, options.chromeMajor),
        getHighEntropyValues: async (hints = []) => {
          const values = {
            architecture: options.secChUaArch || "x86",
            bitness: options.secChUaBitness || "64",
            mobile: false,
            model: options.secChUaModel || "",
            platform: options.userAgentDataPlatform || options.secChUaPlatform || "Windows",
            platformVersion: options.secChUaPlatformVersion || "19.0.0",
            uaFullVersion: options.secChUaFullVersion || options.chromeFullVersion || "",
            fullVersionList: parseSecChBrands(options.secChUaFullVersionList, options.chromeFullVersion || options.chromeMajor),
          };
          if (!Array.isArray(hints) || hints.length === 0) return values;
          const picked = {};
          for (const hint of hints) if (hint in values) picked[hint] = values[hint];
          return picked;
        },
        toJSON() { return { brands: this.brands, mobile: this.mobile, platform: this.platform }; },
      },
    }),
  });
  const localStorage = createStorage();
  const sessionStorage = createStorage();
  const history = {
    length: 1,
    state: null,
    back() {},
    forward() {},
    go() {},
    pushState(state) {
      this.state = state ?? null;
    },
    replaceState(state) {
      this.state = state ?? null;
    },
  };

  async function browserFetch(input, init = {}) {
    const url = typeof input === "string" ? input : (input?.url || String(input));
    const start = browserPerformance.now();
    const isSentinelPing = /\/backend-api\/sentinel\/ping(?:$|[?#])/.test(url);
    if (isSentinelPing) {
      const edge = String(options.cfEdgeMsec ?? 38);
      const origin = String(options.cfOriginTtfbMsec ?? 74);
      const tcp = String(options.cfTcpRttMsec ?? 22);
      const quic = String(options.cfQuicRttMsec ?? 0);
      const duration = Math.max(1, Number(edge) + Number(origin));
      const entry = {
        name: url,
        entryType: "resource",
        initiatorType: "fetch",
        startTime: start,
        requestStart: start + 1,
        responseStart: start + Math.max(1, Number(edge)),
        responseEnd: start + duration,
        duration,
        transferSize: 300,
        encodedBodySize: 0,
        decodedBodySize: 0,
        nextHopProtocol: options.nextHopProtocol || "h2",
        toJSON() { return { ...this }; },
      };
      pushPerformanceEntry(entry);
      return new Response("", {
        status: 204,
        headers: {
          "s-cf-edge-msec": edge,
          "s-cf-origin-ttfb-msec": origin,
          "s-cf-tcp-rtt-msec": tcp,
          "s-cf-quic-rtt-msec": quic,
        },
      });
    }
    const response = await fetch(input, init);
    const end = browserPerformance.now();
    pushPerformanceEntry({
      name: url,
      entryType: "resource",
      initiatorType: init?.method ? String(init.method).toLowerCase() : "fetch",
      startTime: start,
      requestStart: start + 1,
      responseStart: Math.max(start + 1, end - 1),
      responseEnd: end,
      duration: Math.max(1, end - start),
      transferSize: 0,
      encodedBodySize: 0,
      decodedBodySize: 0,
      nextHopProtocol: options.nextHopProtocol || "h2",
      toJSON() { return { ...this }; },
    });
    return response;
  }

  const window = Object.assign(windowTarget, {
    window: null,
    self: null,
    top: null,
    parent: null,
    name: "",
    closed: false,
    length: 0,
    opener: null,
    frames: null,
    focus() {},
    blur() {},
    scrollTo() {},
    scrollBy() {},
    matchMedia(query) { return { matches: false, media: String(query), onchange: null, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {}, dispatchEvent() { return false; } }; },
    getComputedStyle(element) { return element?.style || createStyleDeclaration(); },
    MessageEvent: class MessageEvent { constructor(type, init = {}) { this.type = type; Object.assign(this, init); } },
    Event: class Event { constructor(type, init = {}) { this.type = type; Object.assign(this, init); } },
    CustomEvent: class CustomEvent { constructor(type, init = {}) { this.type = type; this.detail = init.detail; Object.assign(this, init); } },
    DOMRect: class DOMRect { constructor(x = 0, y = 0, width = 0, height = 0) { Object.assign(this, { x, y, width, height, top: y, left: x, right: x + width, bottom: y + height }); } },
    HTMLElement: function HTMLElement() {},
    HTMLIFrameElement: function HTMLIFrameElement() {},
    MutationObserver: class MutationObserver { constructor(callback) { this.callback = callback; } observe() {} disconnect() {} takeRecords() { return []; } },
    PerformanceObserver: createPerformanceObserver(performanceObservers),
    document,
    navigator,
    screen: options.screen,
    location,
    locationbar: { visible: true },
    menubar: { visible: true },
    personalbar: { visible: true },
    scrollbars: { visible: true },
    statusbar: { visible: true },
    toolbar: { visible: true },
    scrollX: 0,
    scrollY: 0,
    localStorage,
    sessionStorage,
    history,
    // 最大化窗口：外框等于屏幕，视口再扣掉窗口装饰（macOS 标签栏较矮）。
    innerWidth: Math.max(320, options.screen.width),
    innerHeight: Math.max(320, options.screen.height - (options.isMacPlatform ? 87 : 91)),
    outerWidth: Math.max(320, options.screen.width),
    outerHeight: Math.max(320, options.screen.height),
    screenX: 0,
    screenY: 0,
    devicePixelRatio: options.devicePixelRatio,
    ...(isSafari ? { safari: { pushNotification: {} } } : { chrome: { runtime: {}, app: {} } }),
    performance: browserPerformance,
    crypto: browserCrypto,
    TextEncoder,
    TextDecoder,
    URL,
    URLSearchParams,
    AbortController,
    setTimeout: managedSetTimeout,
    clearTimeout: managedClearTimeout,
    setInterval: managedSetTimeout,
    clearInterval: managedClearTimeout,
    queueMicrotask: queueMicrotask.bind(globalThis),
    btoa: btoaBinary,
    atob: atobBinary,
    fetch: browserFetch,
    console,
    Math: mathObject,
    Date,
    Intl: browserIntl,
    AudioContext: createAudioContext(),
    webkitAudioContext: createAudioContext(),
    JSON,
    Array,
    Object,
    Reflect,
    Number,
    String,
    Promise,
    RegExp,
    Error,
    Map,
    Set,
    WeakMap,
    Uint8Array,
    encodeURIComponent,
    decodeURIComponent,
    unescape,
    ...(exposeRequestIdleCallback ? {
      requestIdleCallback(callback) {
        return managedSetTimeout(() => callback({ timeRemaining: () => 5, didTimeout: false }), 0);
      },
      cancelIdleCallback(id) {
        managedClearTimeout(id);
      },
    } : {}),
    requestAnimationFrame(callback) {
      return managedSetTimeout(() => callback(performance.now()), 16);
    },
    cancelAnimationFrame(id) {
      managedClearTimeout(id);
    },
    webkitRequestAnimationFrame(callback) {
      return this.requestAnimationFrame(callback);
    },
    __privateStripeFrame8094: {},
    onpageswap: null,
    ondevicemotion: null,
    onlostpointercapture: null,
    onratechange: null,
    oncanplay: null,
    onpagehide: null,
    onpageshow: null,
    onvisibilitychange: null,
    onfocus: null,
    onblur: null,
    onbeforeunload: null,
    onload: null,
    onunload: null,
    onresize: null,
    onscroll: null,
    onwheel: null,
    onkeydown: null,
    onkeyup: null,
    onmousedown: null,
    onmouseup: null,
    onmousemove: null,
    onpointerdown: null,
    onpointermove: null,
    onpointerup: null,
    origin: location.origin,
    isSecureContext: true,
    crossOriginIsolated: false,
    visualViewport: { width: options.screen.width, height: options.screen.height, offsetLeft: 0, offsetTop: 0, pageLeft: 0, pageTop: 0, scale: 1, addEventListener() {}, removeEventListener() {} },
    speechSynthesis: { pending: false, speaking: false, paused: false, getVoices() { return []; }, speak() {}, cancel() {}, pause() {}, resume() {} },
    caches: { has: async () => false, keys: async () => [], open: async () => ({ match: async () => undefined }), delete: async () => false },
    indexedDB: { open() { return { result: null, onsuccess: null, onerror: null }; }, deleteDatabase() { return { onsuccess: null, onerror: null }; } },
    trustedTypes: { createPolicy() { return { createHTML: (s) => s, createScript: (s) => s, createScriptURL: (s) => s }; }, defaultPolicy: null },
    CSS: { supports() { return true; }, escape(s) { return String(s); } },
    styleMedia: { type: "screen" },
    external: { AddSearchProvider() {}, IsSearchProviderInstalled() { return 0; } },
    offscreenBuffering: true,
    clientInformation: navigator,
    releaseEvents() {},
    captureEvents() {},
  });
  installChromeWindowSurface(window);
  window.__oai_so_owner = window;
  seedSessionObserverTelemetry(window, options);
  soDxLog(
    "env keys window=" + Object.keys(window).length +
    " document=" + Object.keys(document).length +
    " navOwn=" + Object.keys(navigator).length +
    " navProto=" + Object.keys(Object.getPrototypeOf(navigator) || {}).length +
    " scripts=" + (document.scripts || []).length +
    " perf=" + (browserPerformance.getEntries() || []).length
  );

  window.window = window;
  window.self = window;
  window.top = window;
  window.parent = window;
  window.frames = window;
  document.defaultView = window;

  return {
    iframeNode: () => iframeNode,
    context: vm.createContext({
      window,
      self: window,
      globalThis: window,
      document,
      navigator,
      screen: options.screen,
      location,
      localStorage,
      sessionStorage,
      history,
      performance: browserPerformance,
      crypto: browserCrypto,
      TextEncoder,
      TextDecoder,
      URL,
      URLSearchParams,
      AbortController,
      MessageEvent: window.MessageEvent,
      Event: window.Event,
      CustomEvent: window.CustomEvent,
      DOMRect: window.DOMRect,
      HTMLElement: window.HTMLElement,
      HTMLIFrameElement: window.HTMLIFrameElement,
      MutationObserver: window.MutationObserver,
      PerformanceObserver: window.PerformanceObserver,
      setTimeout: managedSetTimeout,
      clearTimeout: managedClearTimeout,
      setInterval: managedSetTimeout,
      clearInterval: managedClearTimeout,
      queueMicrotask: queueMicrotask.bind(globalThis),
      btoa: btoaBinary,
      atob: atobBinary,
      fetch: browserFetch,
      console,
      Math: mathObject,
      Date,
      Intl: browserIntl,
      AudioContext: window.AudioContext,
      webkitAudioContext: window.webkitAudioContext,
      JSON,
      Array,
      Object,
      Reflect,
      Number,
      String,
      Promise,
      RegExp,
      Error,
      Map,
      Set,
      WeakMap,
      Uint8Array,
      encodeURIComponent,
      decodeURIComponent,
      unescape,
      ...(exposeRequestIdleCallback ? {
        requestIdleCallback: window.requestIdleCallback,
        cancelIdleCallback: window.cancelIdleCallback,
      } : {}),
      requestAnimationFrame: window.requestAnimationFrame,
      cancelAnimationFrame: window.cancelAnimationFrame,
      webkitRequestAnimationFrame: window.webkitRequestAnimationFrame,
      __privateStripeFrame8094: window.__privateStripeFrame8094,
      onpageswap: window.onpageswap,
    }),
    clearTimers() {
      for (const id of [...managedTimers]) managedClearTimeout(id);
    },
  };
}

async function main(argv = process.argv.slice(2), writeOutput = true) {
  const args = readArgs(argv);
  if (args.help === "1" || args.h === "1") {
    const helpText = [
      "用法：",
      "  node sentinel-runner.js --cookie \"你的 Cookie\"",
      "  node sentinel-runner.js --bearer \"Bearer 你的 token\"",
      "  node sentinel-runner.js --cookie \"你的 Cookie\" --bearer \"Bearer 你的 token\"",
      "  node sentinel-runner.js --config sentinel.config.json",
      "",
      "默认会读取当前目录、tools 目录或项目根目录的 sentinel.config.json。",
      "",
      "常用参数：",
      "  --flow checkout_session_approval",
      "  --page-url https://chatgpt.com/checkout/openai_llc/cs_xxx",
      "  --device-id 你的_oai-did",
      "  --challenge-url 自定义题目 challenge API",
      "  --sdk 指定 sdk.js 路径",
      "  --no-cookie 生成 token 时不向 challenge API 发送 Cookie",
    ].join("\n");
    if (writeOutput) process.stdout.write(`${helpText}\n`);
    return helpText;
  }

  const { path: configPath, data: config } = readConfig(args);
  const ignoreEnvForCredentials = Boolean(configPath);
  const cfg = configGetter(config);
  const defaultSdkPath = fs.existsSync(path.resolve(__dirname, "sdk.js"))
    ? path.resolve(__dirname, "sdk.js")
    : path.resolve(__dirname, "..", "sdk.js");
  const sdkPath = path.resolve(pick(args["sdk"], cfg("sdk", "sdkPath"), process.env.SENTINEL_SDK_PATH, defaultSdkPath));
  const flow = pick(args.flow, cfg("flow"), process.env.SENTINEL_FLOW, "checkout_session_approval");
  const challengeFile = pick(args["challenge-file"], cfg("challengeFile", "challenge_file"), process.env.SENTINEL_CHALLENGE_FILE);
  const officialMode =
    args.official === "1" ||
    truthy(cfg("official")) ||
    process.env.SENTINEL_OFFICIAL === "1" ||
    (!challengeFile && !args["challenge-url"] && !cfg("challengeUrl", "challenge_url") && !process.env.SENTINEL_CHALLENGE_URL);
  const challengeUrl =
    pick(args["challenge-url"], cfg("challengeUrl", "challenge_url"), process.env.SENTINEL_CHALLENGE_URL) ||
    (officialMode ? OFFICIAL_CHALLENGE_URL : "");
  const noCookie = args["no-cookie"] === "1" || truthy(cfg("noCookie", "no_cookie"));
  const cookieArg = noCookie ? "" : pick(args.cookie, args.cookies, cfg("cookie", "cookies"));
  const bearerArg = pick(args.bearer, args.authorization, cfg("bearer", "bearerToken", "authorization", "accessToken"));
  const proxyArg = pick(args.proxy, cfg("proxy"), process.env.SENTINEL_PROXY, "");
  const contentType = pick(args["content-type"], cfg("contentType", "content_type"));
  const debugDx = args["debug-dx"] === "1" || truthy(cfg("debugDx", "debug_dx"));
  const debugDxLimit = Number(pick(args["debug-dx-limit"], cfg("debugDxLimit", "debug_dx_limit"), 80));
  const deviceId =
    pick(args["device-id"], cfg("deviceId", "device_id", "oaiDid", "oai_did"), process.env.SENTINEL_OAI_DID) ||
    "8a5ad769-e9e7-4461-ae3a-6755d7f46b0b";

  if (!fs.existsSync(sdkPath)) throw new Error(`找不到 SDK 文件：${sdkPath}`);
  if (!challengeFile && !challengeUrl) {
    throw new Error("请提供 --challenge-file、--challenge-url 或 --official，用于把题目服务器 challenge 喂回 SDK。");
  }

  let cachedChallenge = null;
  const options = {
    flow,
    sentinelSid: pick(args["sentinel-sid"], cfg("sentinelSid", "sentinel_sid"), process.env.SENTINEL_SID, ""),
    pageUrl: pick(args["page-url"], cfg("pageUrl", "page_url"), process.env.SENTINEL_PAGE_URL, "https://chatgpt.com/checkout/openai_llc/cs_ctf"),
    scriptSrc:
      pick(
        args["script-src"],
        cfg("scriptSrc", "script_src"),
        process.env.SENTINEL_SCRIPT_SRC,
      "https://sentinel.openai.com/sentinel/20260810913b/sdk.js",
      ),
    buildId: pick(args["build-id"], cfg("buildId", "build_id"), process.env.SENTINEL_BUILD_ID, ""),
    reactListeningKey: pick(args["react-listening-key"], cfg("reactListeningKey", "react_listening_key"), process.env.SENTINEL_REACT_LISTENING_KEY, ""),
    reactContainerKey: pick(args["react-container-key"], cfg("reactContainerKey", "react_container_key"), process.env.SENTINEL_REACT_CONTAINER_KEY, ""),
    reactResourcesKey: pick(args["react-resources-key"], cfg("reactResourcesKey", "react_resources_key"), process.env.SENTINEL_REACT_RESOURCES_KEY, ""),
    cookie: noCookie
      ? `oai-did=${deviceId}`
      : cookieArg ||
        (ignoreEnvForCredentials ? "" : process.env.SENTINEL_COOKIE || process.env.CHATGPT_COOKIE) ||
        `oai-did=${deviceId}`,
    userAgent:
      pick(
        args["user-agent"],
        cfg("userAgent", "user_agent"),
        process.env.SENTINEL_USER_AGENT,
      DEFAULT_USER_AGENT,
      ),
    contentType,
    browserFamily: pick(args["browser-family"], cfg("browserFamily", "browser_family"), process.env.SENTINEL_BROWSER_FAMILY, "chrome"),
    navigatorPlatform: pick(args["navigator-platform"], cfg("navigatorPlatform", "navigator_platform"), process.env.SENTINEL_NAVIGATOR_PLATFORM, "Win32"),
    navigatorVendor: pick(args["navigator-vendor"], cfg("navigatorVendor", "navigator_vendor"), process.env.SENTINEL_NAVIGATOR_VENDOR, "Google Inc."),
    userAgentDataPlatform: pick(args["user-agent-data-platform"], cfg("userAgentDataPlatform", "user_agent_data_platform"), process.env.SENTINEL_UA_DATA_PLATFORM, "Windows"),
    requestIdleCallback: truthy(pick(args["request-idle-callback"], cfg("requestIdleCallback", "request_idle_callback"), process.env.SENTINEL_REQUEST_IDLE_CALLBACK, "0")),
    language: pick(args.language, cfg("language"), process.env.SENTINEL_LANGUAGE, "ja-JP"),
    languages: normalizeList(pick(args.languages, cfg("languages")), process.env.SENTINEL_LANGUAGES || "ja-JP"),
    timeZone: pick(args["time-zone"], args.timezone, cfg("timeZone", "time_zone", "timezone"), process.env.SENTINEL_TIME_ZONE, "Asia/Tokyo"),
    timezoneName: pick(args["timezone-name"], cfg("timezoneName", "timezone_name"), process.env.SENTINEL_TIMEZONE_NAME, "Japan Standard Time"),
    timezoneOffsetMinutes: Number(pick(args["timezone-offset-minutes"], cfg("timezoneOffsetMinutes", "timezone_offset_minutes"), process.env.SENTINEL_TIMEZONE_OFFSET_MINUTES, 540)),
    hardwareConcurrency: Number(pick(args.cores, cfg("cores", "hardwareConcurrency"), process.env.SENTINEL_CORES, 6)),
    jsHeapSizeLimit: Number(pick(args["js-heap-size-limit"], cfg("jsHeapSizeLimit", "js_heap_size_limit"), process.env.SENTINEL_JS_HEAP_SIZE_LIMIT, 4395630592)),
    fixedRandom:
      pick(args.random, cfg("random", "fixedRandom"), process.env.SENTINEL_FIXED_RANDOM)
        ? Number(pick(args.random, cfg("random", "fixedRandom"), process.env.SENTINEL_FIXED_RANDOM))
        : Number.NaN,
    deviceMemory: Number(pick(args["device-memory"], cfg("deviceMemory", "device_memory"), process.env.SENTINEL_DEVICE_MEMORY, 8)),
    devicePixelRatio: Number(pick(args["device-pixel-ratio"], cfg("devicePixelRatio", "device_pixel_ratio"), process.env.SENTINEL_DEVICE_PIXEL_RATIO, 2)),
    chromeMajor: pick(args["chrome-major"], cfg("chromeMajor", "chrome_major"), process.env.SENTINEL_CHROME_MAJOR, "142"),
    chromeFullVersion: pick(args["chrome-full-version"], cfg("chromeFullVersion", "chrome_full_version"), process.env.SENTINEL_CHROME_FULL_VERSION, "142.0.0.0"),
    secChUa: pick(args["sec-ch-ua"], cfg("secChUa", "sec_ch_ua"), process.env.SENTINEL_SEC_CH_UA, DEFAULT_SEC_CH_UA),
    secChUaPlatform: String(pick(args["sec-ch-ua-platform"], cfg("secChUaPlatform", "sec_ch_ua_platform"), process.env.SENTINEL_SEC_CH_UA_PLATFORM, "Windows")).replace(/^"|"$/g, ""),
    secChUaFullVersionList: pick(args["sec-ch-ua-full-version-list"], cfg("secChUaFullVersionList", "sec_ch_ua_full_version_list"), process.env.SENTINEL_SEC_CH_UA_FULL_VERSION_LIST, DEFAULT_SEC_CH_UA_FULL_VERSION_LIST),
    secChUaFullVersion: String(pick(args["sec-ch-ua-full-version"], cfg("secChUaFullVersion", "sec_ch_ua_full_version"), process.env.SENTINEL_SEC_CH_UA_FULL_VERSION, "142.0.0.0")).replace(/^"|"$/g, ""),
    secChUaPlatformVersion: String(pick(args["sec-ch-ua-platform-version"], cfg("secChUaPlatformVersion", "sec_ch_ua_platform_version"), process.env.SENTINEL_SEC_CH_UA_PLATFORM_VERSION, "19.0.0")).replace(/^"|"$/g, ""),
    secChUaArch: String(pick(args["sec-ch-ua-arch"], cfg("secChUaArch", "sec_ch_ua_arch"), process.env.SENTINEL_SEC_CH_UA_ARCH, "x86")).replace(/^"|"$/g, ""),
    secChUaBitness: String(pick(args["sec-ch-ua-bitness"], cfg("secChUaBitness", "sec_ch_ua_bitness"), process.env.SENTINEL_SEC_CH_UA_BITNESS, "64")).replace(/^"|"$/g, ""),
    secChUaModel: String(pick(args["sec-ch-ua-model"], cfg("secChUaModel", "sec_ch_ua_model"), process.env.SENTINEL_SEC_CH_UA_MODEL, "")).replace(/^"|"$/g, ""),
    cfEdgeMsec: Number(pick(args["cf-edge-msec"], cfg("cfEdgeMsec", "cf_edge_msec"), process.env.SENTINEL_CF_EDGE_MSEC, 38)),
    cfOriginTtfbMsec: Number(pick(args["cf-origin-ttfb-msec"], cfg("cfOriginTtfbMsec", "cf_origin_ttfb_msec"), process.env.SENTINEL_CF_ORIGIN_TTFB_MSEC, 74)),
    cfTcpRttMsec: Number(pick(args["cf-tcp-rtt-msec"], cfg("cfTcpRttMsec", "cf_tcp_rtt_msec"), process.env.SENTINEL_CF_TCP_RTT_MSEC, 22)),
    cfQuicRttMsec: Number(pick(args["cf-quic-rtt-msec"], cfg("cfQuicRttMsec", "cf_quic_rtt_msec"), process.env.SENTINEL_CF_QUIC_RTT_MSEC, 0)),
    // 桌面 Chrome：屏幕可用高度要扣掉系统栏（macOS 顶栏 25px / Windows 任务栏 40px），
    // 窗口视口又要在外框里再扣掉标签栏+工具栏。之前 innerHeight 直接等于整屏高度、
    // outerHeight 还比屏幕高 88px —— JS 里一眼就能看出几何不可能。
    isMacPlatform: (() => {
      const platform = String(pick(args["sec-ch-ua-platform"], cfg("secChUaPlatform", "sec_ch_ua_platform"), process.env.SENTINEL_SEC_CH_UA_PLATFORM, "Windows"));
      const navPlatform = String(pick(args["navigator-platform"], cfg("navigatorPlatform", "navigator_platform"), process.env.SENTINEL_NAVIGATOR_PLATFORM, "Win32"));
      const uaDataPlatform = String(pick(args["user-agent-data-platform"], cfg("userAgentDataPlatform", "user_agent_data_platform"), process.env.SENTINEL_UA_DATA_PLATFORM, "Windows"));
      const ua = String(pick(args["user-agent"], cfg("userAgent", "user_agent"), process.env.SENTINEL_USER_AGENT, ""));
      return /mac/i.test(platform) || /mac/i.test(navPlatform) || /mac/i.test(uaDataPlatform) || /Macintosh/i.test(ua);
    })(),
    screen: (() => {
      const width = Number(pick(args.width, cfg("width", "screenWidth"), process.env.SENTINEL_SCREEN_WIDTH, 1680));
      const height = Number(pick(args.height, cfg("height", "screenHeight"), process.env.SENTINEL_SCREEN_HEIGHT, 1050));
      const platform = String(pick(args["sec-ch-ua-platform"], cfg("secChUaPlatform", "sec_ch_ua_platform"), process.env.SENTINEL_SEC_CH_UA_PLATFORM, "Windows"));
      const macLike = /mac/i.test(platform) || /Macintosh/i.test(String(pick(args["user-agent"], cfg("userAgent", "user_agent"), process.env.SENTINEL_USER_AGENT, "")));
      const availInset = macLike ? 25 : 40;
      return {
        width,
        height,
        availWidth: width,
        availHeight: Math.max(0, height - availInset),
        // 桌面 Chrome 基本都是 24 位色；30 位只在 10bit HDR 机器上出现。
        colorDepth: 24,
        pixelDepth: 24,
        orientation: { type: "landscape-primary", angle: 0 },
      };
    })(),
    async handleIframeMessage(message) {
      if (message.type !== "token" && message.type !== "init") {
        throw new Error(`未知 iframe 消息类型：${message.type}`);
      }
      const proof = message.p;
      const liveChallengeUrl = challengeUrl || "https://sentinel.openai.com/backend-api/sentinel/req";
      if (challengeFile && !cachedChallenge) {
        cachedChallenge = readChallengeFile(challengeFile);
      }
      const existingP = String(cachedChallenge && cachedChallenge._requirements_p || "");
      const needLive = Boolean(proof) && existingP !== String(proof || "");
      if (needLive) {
        try {
          cachedChallenge = await fetchChallenge(liveChallengeUrl, flow, proof, deviceId, {
            officialMode: true,
            pageUrl: options.pageUrl,
            userAgent: options.userAgent,
            cookie: noCookie ? "" : cookieArg,
            bearer: bearerArg,
            contentType: "text/plain;charset=UTF-8",
            ignoreEnv: ignoreEnvForCredentials,
            proxy: proxyArg,
          });
          soDxLog("live challenge dx turnstile=" + String((cachedChallenge.turnstile && cachedChallenge.turnstile.dx) || "").length + " collector=" + String((cachedChallenge.so && cachedChallenge.so.collector_dx) || "").length);
        } catch (error) {
          soDxLog("live challenge fail " + (error && error.message || error));
          if (!cachedChallenge && challengeFile) cachedChallenge = readChallengeFile(challengeFile);
        }
      } else if (!cachedChallenge && challengeFile) {
        cachedChallenge = readChallengeFile(challengeFile);
      }
      if (debugDx && cachedChallenge?.turnstile?.dx) {
        try {
          const decoded = decodeDx(cachedChallenge.turnstile.dx, proof);
          const limit = Number.isFinite(debugDxLimit) && debugDxLimit > 0 ? debugDxLimit : 80;
          process.stderr.write(`dx 前 ${limit} 条指令：${JSON.stringify(decoded.slice(0, limit))}\n`);
        } catch (error) {
          process.stderr.write(`dx 解码失败：${error.message}\n`);
        }
      }
      const boundProof = String(cachedChallenge?._requirements_p || proof || "");
      // 关键：turnstile DX 的输出必须是 XOR(trace, p) 的二进制串，SDK 才会 btoa 成 t。
      // 不在这里绑 key，DX 会吐出明文 trace，t 解出来可打印但不是 XOR 结构（长度也短）。
      try {
        const scope = context.window || context.globalThis || context;
        const binder = scope.D || context.D;
        if (typeof binder === "function" && cachedChallenge && boundProof) {
          binder(cachedChallenge, boundProof);
          soDxLog("bound D(challenge, key) len=" + boundProof.length + " type=" + message.type);
        } else {
          soDxLog("D not available type=" + typeof binder + " type=" + message.type);
        }
      } catch (error) {
        soDxLog("D bind failed " + (error && error.message || error));
      }
      try {
        process.stderr.write(
          "so-dx: iframe type=" + message.type +
          " proof=" + String(proof || "").slice(0, 12) +
          " python_p=" + String(cachedChallenge && cachedChallenge._requirements_p || "").slice(0, 12) +
          " match=" + String(String(proof || "") === String(cachedChallenge && cachedChallenge._requirements_p || "")) +
          "\n"
        );
      } catch {}
      return {
        cachedProof: boundProof,
        cachedChatReq: cachedChallenge,
      };
    },
  };

  if (options.timeZone) {
    process.env.TZ = options.timeZone;
  }

  const { context, clearTimers } = createBrowserContext(options);
  let sdkCode = fs.readFileSync(sdkPath, "utf8");
  // sdk.js 里 turnstile DX 默认 500ms 就 abort；这里替换成长跑值，不改指令语义。
  // 实测（2026-09-12，email_otp_validate）：把时长设成 1000/4000/12000/30000ms，
  // t 分别是 1112/1064/1020/1092 —— 在这个量级上时长对 t 长度没有影响，
  // 所以它只是可调参数（SENTINEL_DX_RUN_MS），不是 t 偏短的原因。
  // 真浏览器 t=1348，缺口来自别处（环境观测值本身，不是条目数/键缺失/时长）。
  const dxRunMs = Number(process.env.SENTINEL_DX_RUN_MS || 4000) || 4000;
  sdkCode = mustReplace(sdkCode, "}),500)", "})," + dxRunMs + ")", "DX_RUN_MS");
  // ⚠️ 2026-09-22：这个锚点是**历史 SDK 版本的遗留**，当前 sdk.js 里连标识符 Cn 都不存在
  //    （全文件只有 1 处 .bind(，是 crypto.getRandomValues.bind）。也就是说这处补丁
  //    已经静默失效很久了 —— 旧代码用裸 replace() 所以谁都没发现。
  //    它本来只是防御性的（bind 到非函数时降级成 no-op，别抛 TypeError），
  //    当前版本没有对应代码路径，所以改成 optionalReplace：留警告、不中断。
  //    真正保命的是下面加载后的 POST-LOAD CHECK。
  sdkCode = optionalReplace(
    sdkCode,
    "Cn.set(n,Cn.get(e)[Cn.get(r)].bind(Cn[t(24)](e)))",
    "(()=>{const __o=Cn.get(e),__p=Cn.get(r);if(!__o||typeof __o[__p]!=='function'){console.error('[dx bind missing]',typeof __o,__p);return Cn.set(n,function(){return undefined;});}return Cn.set(n,__o[__p].bind(__o));})()",
    "DX_BIND"
  );
  const tokenExportNeedle = "t.token=je,t}({})";
  sdkCode = mustReplace(
    sdkCode,
    tokenExportNeedle,
    "t.token=je,(function(){try{var g=(typeof window!=='undefined'&&window)||(typeof self!=='undefined'&&self)||this;if(g){g.Et=Et;g.qt=qt;g.F=F;g.D=D;}}catch(e){}})(),t}({})",
    "EXPOSE"
  );
  vm.runInContext(sdkCode, context, { filename: sdkPath });

  // ─── Hook 生效校验（「替换命中」≠「出口可用」）────────────────────────────
  // SDK 可能在别处遮蔽/重赋值，或锚点命中了但不是我们要的那处。加载后按类型硬校验，
  // 缺任何一个就 exit 3 —— 这样「hook 断了」和「PoW 算不出来」在日志里再也不会长得一样。
  const hookTypes = {
    SentinelSDK: typeof context.SentinelSDK,
    token: typeof context.SentinelSDK?.token,
    Et: typeof (context.Et || context.window?.Et),
    qt: typeof (context.qt || context.window?.qt),
    F: typeof (context.F || context.window?.F),
    D: typeof (context.D || context.window?.D),
  };
  const hookMissing = [];
  if (hookTypes.SentinelSDK === "undefined") hookMissing.push("globalThis.SentinelSDK");
  if (hookTypes.token !== "function") hookMissing.push("SentinelSDK.token (want function, got " + hookTypes.token + ")");
  for (const name of ["Et", "qt", "F", "D"]) {
    if (hookTypes[name] !== "function") hookMissing.push(name + " (want function, got " + hookTypes[name] + ")");
  }
  if (hookMissing.length) {
    const degrade = process.env.SENTINEL_ALLOW_DEGRADED === "1";
    process.stderr.write(
      "[sentinel-hook] POST-LOAD CHECK FAILED: " + hookMissing.join("; ") + "\n" +
      "[sentinel-hook] 三处替换字符串需按当前 sdk.js 重新定位。\n"
    );
    if (!degrade) {
      process.stderr.write(
        "[sentinel-hook] 拒绝继续（exit " + HOOK_EXIT_CODE + "）。\n" +
        "[sentinel-hook] 确实要带半个 hook 跑（会退回 sessionObserverToken，so 会偏短）：" +
        "SENTINEL_ALLOW_DEGRADED=1\n"
      );
      process.exit(HOOK_EXIT_CODE);
    }
    process.stderr.write("[sentinel-hook] SENTINEL_ALLOW_DEGRADED=1，带伤继续，so 可能偏短\n");
  }
  if (process.env.SENTINEL_HOOK_DEBUG) {
    process.stderr.write("[sentinel-hook] OK " + JSON.stringify(hookTypes) + "\n");
  }
  const tokenText = await context.SentinelSDK.token(flow);
  let outputText = tokenText;
  try {
    const parsed = JSON.parse(tokenText);
    try {
      const xorKey = String(cachedChallenge && cachedChallenge._requirements_p || "");
      if (parsed && parsed.t) {
        const rate = (text) => (Array.from(text).filter((ch) => {
          const c = ch.charCodeAt(0);
          return c >= 32 && c < 127;
        }).length / Math.max(1, text.length)).toFixed(3);
        try {
          const once = atobBinary(String(parsed.t));
          soDxLog("t b64x1 printable=" + rate(once) + " len=" + once.length);
          let twice = "";
          try { twice = atobBinary(once); } catch {}
          if (twice) soDxLog("t b64x2 printable=" + rate(twice) + " len=" + twice.length);
          const keys = [["req_p", xorKey], ["token_p", String(parsed.p || "")]];
          for (const [name, key] of keys) {
            if (!key) continue;
            for (const [depth, src] of [["x1", once], ["x2", twice]]) {
              if (!src) continue;
              const decoded = xorDecodeFromBinary(src, key);
              soDxLog("t " + depth + " xor " + name + " printable=" + rate(decoded) + " len=" + decoded.length);
            }
          }
        } catch (error) {
          soDxLog("t decode fail " + (error && error.message || error));
        }
      }
    } catch (error) {
      soDxLog("t xor fail " + (error && error.message || error));
    }
    const soBlob = await mintSessionObserverBlob(context, cachedChallenge, parsed);
    if (parsed && typeof parsed === "object" && soBlob) {
      parsed.so = soBlob;
      outputText = JSON.stringify(parsed);
    }
  } catch {
    outputText = tokenText;
  }
  clearTimers();
  if (!writeOutput) return outputText;
  if (args.pretty || process.env.SENTINEL_PRETTY === "1") {
    process.stdout.write(`${JSON.stringify(JSON.parse(outputText), null, 2)}\n`);
  } else {
    process.stdout.write(`${outputText}\n`);
  }
  return outputText;
}

if (require.main === module) {
  main().catch((error) => fail(error?.stack || error?.message || String(error)));
}

module.exports = {
  main,
  normalizeChallenge,
};
