# Xerosploit-NG — Port Specification (Python 3 + bettercap v2)

Status: authoritative interface contract for the port. Any lane touching the repo MUST follow this.

## 1. Purpose

Revive `LionSec/xerosploit` on modern Linux (Kali rolling, Parrot OS, Ubuntu, Debian).
The bundled **bettercap v1 (Ruby, invoked as `xettercap`)** is removed and replaced by
**bettercap v2 (Go)**. The interactive menu/UX is preserved. License stays **GPLv3** and
upstream credits (LionSec / Neodrix) are kept.

## 2. Target repository layout

```
xerosploit-ng/
  xerosploit.py          # interactive menu (python3)
  banner.py              # ascii banner (python3)
  install.py             # installer (apt + pip3), multi-distro
  run.sh                 # launches python3 <BASE_DIR>/xerosploit.py
  Makefile               # `make install` -> /opt/xerosploit
  lib/engine.py          # NEW: bettercap v2 orchestrator
  modules/               # NEW: bettercap v2 JS proxy modules
    injecthtml.js  deface.js  injectjs.js  shakescreen.js
    replace_file.js  replace_images.js  rickroll.js
  tools/
    files/               # gateway.txt iface.txt dns.conf
    log/                 # scan.txt pscan.txt ping.txt ...
    tmp/                 # runtime scratch only
  docs/PORT-SPEC.md
  README.md  LICENSE
```

`tools/bettercap/**` (v1 Ruby engine) is DELETED at the end of the port.

## 3. Paths & BASE_DIR

* `BASE_DIR` = absolute directory of the running `xerosploit.py` (so it works both from the
  git checkout and from `/opt/xerosploit`).
* Derive: `TOOLS_DIR=BASE_DIR/tools`, `FILES_DIR=tools/files`, `LOG_DIR=tools/log`,
  `TMP_DIR=tools/tmp`, `MODULES_DIR=BASE_DIR/modules`, `ENGINE=...` .
* No hardcoded `/opt/xerosploit` anywhere except `run.sh` and the `Makefile` install target.

## 4. Engine contract — `lib/engine.py`

Single place that knows how to talk to bettercap. UI code must never build bettercap command
strings itself.

```python
BASE_DIR: str

def bettercap_bin() -> str            # resolve `bettercap`, raise EngineError if missing
def script(module_file: str) -> str   # abs path under MODULES_DIR

# command builders -> list[str] of bettercap session commands
def arp_spoof(targets, internal=True, fullduplex=True) -> list[str]
def http_proxy(script=None, injectjs=None, port=8080, sslstrip=False, address=None) -> list[str]
def https_proxy(sslstrip=False) -> list[str]
def net_sniff(output=None, local=False, verbose=True) -> list[str]
def dns_spoof(domains, address) -> list[str]
def write_runtime_module(module_file, params: dict) -> str   # see §6

# runner -> blocks until bettercap exits (Ctrl+C), returns exit code
def run(iface, commands, logfile=None, caplet=None, extra_eval=None) -> int
```

`run()` composes: `bettercap -iface <iface> -eval "<cmd; cmd; ...>"` (or `-caplet <file>` plus
`-eval`), streams output to stdout/tail, and returns when bettercap exits. Ctrl+C must reach
bettercap so it restores the ARP cache. Use `subprocess.call` (not `os.system`).

## 5. bettercap v2 command mapping

| UI function (py) | old v1 | new v2 |
|---|---|---|
| `scan` / `pscan` | `nmap` | `nmap` unchanged (`-sn gateway/24`, `-Pn target`) |
| `dos` | `hping3` | `hping3` unchanged |
| `ping` | `ping` | `ping` unchanged |
| `snif` | `xettercap --proxy -P MYSQL,...` | `arp_spoof` + `net_sniff(output,local=False)` + `http_proxy()` |
| `snif_sslstrip` | v1 proxy | `http_proxy(sslstrip=True)` + `https_proxy()` |
| `dspoof` | `--dns dns.conf --custom-parser DNS` | `dns_spoof(domains, address)` |
| `inject_html` | `injecthtml.rb` | `http_proxy(script=write_runtime_module("injecthtml.js", {"target_file": ...}))` |
| `deface` | `injecthtml.rb` | `http_proxy(script=write_runtime_module("deface.js", {...}))` |
| `inject_j` | `injectjs.rb --js-file` | `http_proxy(injectjs=<path-or-raw-js>)` (built-in v2) |
| `shakescreen` | `injectjs.rb shakescreen.js` | `http_proxy(injectjs=script("shakescreen.js"))` |
| `rdownload` | `replace_file.rb --file-extension` | `http_proxy(script=write_runtime_module("replace_file.js", {"extensions": [...]}))` |
| `replace` | `replace_images.rb --httpd` | `http_proxy(script=write_runtime_module("replace_images.js", {"image_file": ...}))` |
| `yplay` | `rickroll.rb` | `http_proxy(script=write_runtime_module("rickroll.js", {"video_id": ...}))` |
| `driftnet` | `xettercap -X` + `driftnet` | `net_sniff()` + run `driftnet -d <dir>` |

Every MITM module must first run the ARP-spoof commands for the selected target.

## 6. Proxy JS module contract

* Modules live in `modules/*.js` and are loaded with `set http.proxy.script <abs path>`.
* bettercap provides: `onLoad()`, `onRequest(req,res)`, `onResponse(req,res)`,
  `res.ReadBody()`, `res.Body`, `res.ContentType`, `res.Status`, `res.Headers`,
  `res.SetHeader(k,v)`, `res.RemoveHeader(k)`, `readFile(path)`, `log_info/log_debug/log_warn/log_error`.
* **Parameter passing:** modules MUST read their parameters from pre-declared globals
  (never hardcode paths). `engine.write_runtime_module(module_file, params)` writes
  `tools/tmp/proxy-<name>.js` = a generated preamble, e.g.

  ```js
  // generated preamble
  var XE_BASE_DIR   = "/opt/xerosploit";
  var XE_TMP_DIR    = "/opt/xerosploit/tools/tmp";
  var XE_TARGET_FILE = "/opt/xerosploit/tools/tmp/file.html";
  // >>> module body below <<<
  ```

  followed by the verbatim body of `modules/<module_file>`. Parameter globals are generated
  from `params` as `XE_<UPPER>` (e.g. `target_file` -> `XE_TARGET_FILE`, `extensions` -> a JS array).
* Module bodies must be self-contained (no `require`), tolerant of missing params, and only
  mutate responses of the intended content type.
* Keep an unmodified passthrough when the module's condition is not met (never break traffic).

## 7. Installer (`install.py`)

* apt family (Kali/Parrot/Ubuntu/Debian): `apt-get update && apt-get install -y bettercap nmap hping3 driftnet python3-pip`.
* `pip3 install --break-system-packages tabulate terminaltables` OR apt
  `python3-tabulate python3-terminaltables` (prefer apt when packages exist).
* Copy tree -> `/opt/xerosploit`, copy `run.sh` -> `/usr/bin/xerosploit` (chmod +x).
* If `bettercap` is not in the distro repos, print clear guidance (Kali/Parrot have it).

## 8. Python 2 -> Python 3 checklist

* shebang `#!/usr/bin/env python3`; `run.sh` uses `python3`.
* No py2 leftovers: no print-statements, no `raw_input`, no `except X, e`, no `iteritems`.
* Existing `input()` usage is kept (it is already py3-correct).
* Guard binary file writes (`ximage.png`) with `open(..., "wb")`.

## 9. Verification

* `python3 -m py_compile xerosploit.py banner.py install.py lib/engine.py`
* AST-parse every `.py`; `node --check` (if available) or syntax review for every `.js`.
* Unit-compose engine commands (no network) and assert expected strings.
* Real end-to-end test only on Kali Live (documented separately).

## 10. Do / Don't

* No new dependencies beyond: bettercap, nmap, hping3, driftnet, tabulate, terminaltables.
* Keep GPLv3 and upstream credits.
* Keep the user-visible ASCII menu wording.
* Missing bettercap must fail loudly with a clear message, never silently.
