"use strict";

// ─── 目标时区 / 页面 locale 画像 ────────────────────────────────────────────
// 本文件是 sentinel/sentinel-runner.js 与 tools/sentinel_tzprobe.js 的**唯一真源**：
// 探针跑的就是生产代码，不会出现「探针绿、生产红」。
//
// 为什么不能只靠 process.env.TZ（2026-09-22 实测，node v24.16.0 / ICU 78.3）：
//   1) TZ 只解决**偏移**。设 TZ=Asia/Ho_Chi_Minh 后 getTimezoneOffset() 确实正确
//      返回 -420 —— 这一步是对的，保留。
//   2) 但 Date.toString() 括号里那段是 **ICU 长名，且跟着 node 的默认 locale 走**。
//      本机 node 默认 locale = zh-CN（Windows 系统 locale），原生输出是
//        "Tue Sep 22 2026 20:38:26 GMT+0700 (中南半岛时间)"   ← 中文！
//      这比「时区不一致」更硬：头部声称越南，Date 里蹦出中文时区名。
//   3) LC_ALL / LANG 在 Windows 上对 node **无效**（实测三种写法都不变），
//      --icu-locale 不是合法 node flag。所以只能在 JS 层显式传 locale。
//
// ICU 长名实测（与真 Chrome 148/153 基线一致）：
//   en-US -> Indochina Time      vi-VN -> Giờ Đông Dương
//   th-TH -> เวลาอินโดจีน          id-ID -> Waktu Indochina
//   pt-BR -> Horário da Indochina
//
// IANA 规范化也是实测结论：真 Chrome 传 Asia/Ho_Chi_Minh 报 Asia/Saigon，
// 传 Asia/Kolkata 报 Asia/Calcutta（Chromium 148 + 系统 Chrome 153 一致）。
// node/ICU 78.3 的答案与之一致，所以直接借真 ICU 做规范化，别自己映射。
// ⚠️ 教训：凭 CLDR 版本号想当然推断「规范名已改成 Asia/Ho_Chi_Minh」是**反的**。

const _DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const _MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

const pad2 = (n) => String(n).padStart(2, "0");

// 目标时区在**当前这一刻**的偏移（含夏令时），单位分钟，符号 = 墙上时间 - UTC。
// 越南 = +420；注意 getTimezoneOffset() 返回的是相反的 -420。
function tzOffsetMinutes(timeZone, OrigDTF = Intl.DateTimeFormat) {
  try {
    const dtf = new OrigDTF("en-US", {
      timeZone, hour12: false,
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
    const parts = {};
    for (const p of dtf.formatToParts(new Date())) parts[p.type] = p.value;
    const asUTC = Date.UTC(
      Number(parts.year), Number(parts.month) - 1, Number(parts.day),
      Number(parts.hour) % 24, Number(parts.minute), Number(parts.second),
    );
    return Math.round((asUTC - Math.floor(Date.now() / 1000) * 1000) / 60000);
  } catch (_) {
    return 0;
  }
}

// ICU 长时区名，跟**页面 locale** 走。拿不到就返回 null，由调用方退化成 "GMT+07:00"。
function tzLongName(timeZone, locale, OrigDTF = Intl.DateTimeFormat) {
  try {
    const part = new OrigDTF(locale, { timeZone, timeZoneName: "long" })
      .formatToParts(new Date()).find((p) => p.type === "timeZoneName");
    return part ? part.value : null;
  } catch (_) {
    return null;
  }
}

function computeTzProfile(options = {}) {
  const target = String(options.timeZone || "UTC");
  const locale = String(options.language || "en-US");
  const OrigDTF = Intl.DateTimeFormat;

  // 真 ICU 规范化。与真 Chrome 行为一致（见文件头注释）。
  let canonical = target;
  try {
    canonical = new OrigDTF("en-US", { timeZone: target }).resolvedOptions().timeZone;
  } catch (_) { /* 非法 IANA 名，原样透传 */ }

  const offsetMin = tzOffsetMinutes(target, OrigDTF);
  const longName = tzLongName(target, locale, OrigDTF);

  const sign = offsetMin >= 0 ? "+" : "-";
  const abs = Math.abs(offsetMin);
  const label = "GMT" + sign + pad2(Math.floor(abs / 60)) + pad2(abs % 60);
  const long = "GMT" + sign + pad2(Math.floor(abs / 60)) + ":" + pad2(abs % 60);

  return {
    target,
    canonical,
    locale,
    offsetMin,
    label,                       // GMT+0700
    long,                        // GMT+07:00
    longName,                    // Indochina Time / Giờ Đông Dương / null
    paren: longName || long,     // toString 括号里那一段
  };
}

// 把真实 UTC 毫秒平移到「目标时区的墙上时间」，再用 getUTC* 读出来。
function shifted(ms, offsetMin) {
  return new Date(Number(ms) + offsetMin * 60000);
}

// 纯函数格式化，不碰任何全局原型 —— 探针直接用它做并排对比。
function formatDate(profile, ms) {
  const d = shifted(ms, profile.offsetMin);
  const date = _DAYS[d.getUTCDay()] + " " + _MONTHS[d.getUTCMonth()] + " " + pad2(d.getUTCDate())
    + " " + d.getUTCFullYear();
  const time = pad2(d.getUTCHours()) + ":" + pad2(d.getUTCMinutes()) + ":" + pad2(d.getUTCSeconds())
    + " " + profile.label + " (" + profile.paren + ")";
  return { toString: date + " " + time, toDateString: date, toTimeString: time };
}

// 就地给一个 Date 构造器打时区补丁。返回原生方法表，便于回滚/测试。
function applyDateTimezone(DateCtor, options = {}) {
  const profile = computeTzProfile(options);
  const native = {
    getTimezoneOffset: DateCtor.prototype.getTimezoneOffset,
    toString: DateCtor.prototype.toString,
    toTimeString: DateCtor.prototype.toTimeString,
    toDateString: DateCtor.prototype.toDateString,
  };

  DateCtor.prototype.getTimezoneOffset = function getTimezoneOffset() {
    return -profile.offsetMin;
  };
  DateCtor.prototype.toString = function toString() {
    try {
      return formatDate(profile, this.getTime()).toString;
    } catch (_) {
      return native.toString.call(this);
    }
  };
  DateCtor.prototype.toTimeString = function toTimeString() {
    try {
      return formatDate(profile, this.getTime()).toTimeString;
    } catch (_) {
      return native.toTimeString.call(this);
    }
  };
  DateCtor.prototype.toDateString = function toDateString() {
    try {
      return formatDate(profile, this.getTime()).toDateString;
    } catch (_) {
      return native.toDateString.call(this);
    }
  };

  return { profile, native };
}

// ─── 默认 locale 加固 ──────────────────────────────────────────────────────
// node 在 Windows 上的默认 locale 是**系统 locale**（本机 zh-CN），且无法用
// LC_ALL/LANG/--icu-locale 改。于是 vm 里任何**不显式传 locale** 的调用都会
// 吐出中文格式：
//     (1234.5).toLocaleString()  -> "1,234.5"   （数字侥幸没露馅）
//     new Date().toLocaleString() -> "2026/9/22 21:38:41"  ← zh-CN 顺序
// 真浏览器在 navigator.language=vi-VN 下是 "21:38:41 22/9/2026"。
// 这里把三个宿主对象的 toLocale* 绑死到页面 locale，堵住这条泄漏。
function applyLocaleDefaults(target, options = {}) {
  const locale = String(options.language || "en-US");
  const languages = Array.isArray(options.languages) && options.languages.length
    ? options.languages.slice()
    : [locale];
  const withLocale = (args) => (args.length && args[0] != null) ? args : [locale, ...args];

  const patch = (obj, name) => {
    const native = obj[name];
    if (typeof native !== "function") return;
    Object.defineProperty(obj, name, {
      configurable: true,
      writable: true,
      value: function (...args) { return native.apply(this, withLocale(args)); },
    });
  };

  patch(Number.prototype, "toLocaleString");
  patch(BigInt.prototype, "toLocaleString");
  patch(Date.prototype, "toLocaleString");
  patch(Date.prototype, "toLocaleDateString");
  patch(Date.prototype, "toLocaleTimeString");
  patch(Array.prototype, "toLocaleString");
  try { patch(String.prototype, "localeCompare"); } catch (_) { /* 只读，忽略 */ }

  // 原生 Intl 的「无参默认 locale」也一起扳正。
  try {
    const OrigDTF = Intl.DateTimeFormat;
    const OrigNum = Intl.NumberFormat;
    const wrap = (Orig, name) => {
      const Patched = function (locales, opts) { return new Orig(locales || languages, opts); };
      Patched.prototype = Orig.prototype;
      Object.setPrototypeOf(Patched, Orig);
      if (typeof Orig.supportedLocalesOf === "function") Patched.supportedLocalesOf = Orig.supportedLocalesOf;
      Intl[name] = Patched;
    };
    wrap(OrigDTF, "DateTimeFormat");
    wrap(OrigNum, "NumberFormat");
  } catch (_) { /* Intl 被冻结时忽略 */ }

  return { locale, languages };
}

module.exports = {
  computeTzProfile,
  formatDate,
  applyDateTimezone,
  applyLocaleDefaults,
  tzOffsetMinutes,
  tzLongName,
};
