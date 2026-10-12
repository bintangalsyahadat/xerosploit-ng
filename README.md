<p align="center">
  <strong>Xerosploit-NG</strong><br>
  <em>Modern port of LionSec/xerosploit — Python 3 + bettercap v2</em>
</p>

[![Version](https://img.shields.io/badge/Xerosploit--NG-2.0-brightgreen.svg?maxAge=259200)]()
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)]()
[![bettercap](https://img.shields.io/badge/bettercap-v2-blueviolet.svg)]()
[![Supported OS](https://img.shields.io/badge/Supported_OS-Linux-orange.svg)]()
[![License](https://img.shields.io/github/license/LionSec/xerosploit.svg)](LICENSE)

# Xerosploit-NG

Xerosploit is a penetration testing toolkit whose goal is to perform man-in-the-middle
attacks for testing purposes. It brings various modules that allow to realise efficient
attacks, and also allows to carry out denial of service attacks and port scanning.

**Xerosploit-NG** is a revived fork of [LionSec/xerosploit](https://github.com/LionSec/xerosploit)
(continuing the [Neodrix/Xerosploit](https://github.com/Neodrix/Xerosploit) lineage) for modern
Linux: the outdated bundled **bettercap v1 (Ruby, `xettercap`)** has been removed and replaced by
**bettercap v2 (Go)**, and the menu/UX has been ported to **Python 3**. It is powered by
[bettercap](https://www.bettercap.org) and [nmap](https://nmap.org). Xerosploit-NG is distributed
under the **GNU General Public License v3 (GPLv3)**.

> ⚠️ **Use only against systems you own or are explicitly authorised to test.** MITM attacks
> disrupt traffic and are illegal without permission.

---

## Dependencies

Xerosploit-NG relies on the following tools (installed automatically by `install.py`):

- **bettercap v2** (Go) — the MITM engine and HTTP/HTTPS proxy
- **nmap** — network / port scanning
- **hping3** — Denial of Service module
- **driftnet** — image sniffing
- **python3** (3.9+) with **pip3**

**`tabulate` and `terminaltables` are optional.** They are used only for the menu's table
output. When they are absent the tool still starts: `xerosploit.py` prints a single warning
and renders the tables with a built-in ASCII renderer, and `install.py` treats their
installation as non-fatal.

---

## Supported operating systems

| Distribution | Notes |
|---|---|
| **Kali Linux** (rolling) | `bettercap` is in the repositories |
| **Parrot OS** | `bettercap` is in the repositories |
| **Ubuntu** (20.04+) | `bettercap` may need the upstream release if absent from apt |
| **Debian** (11+) | `bettercap` may need the upstream release if absent from apt |

---

## Installation

This fork does not have a public remote configured yet, so obtain the source from
`<xerosploit-ng-repository-url>` (a local checkout copy works identically):

```bash
git clone <xerosploit-ng-repository-url>
cd xerosploit-ng
sudo python3 install.py
```

The installer installs the dependencies, copies the tree to `/opt/xerosploit`, and installs
the `xerosploit` launcher into `/usr/bin`.

No install step is required to run from the checkout — the paths are resolved relative to the
running script:

```bash
sudo python3 xerosploit.py
```

Packagers can use the Makefile instead:

```bash
sudo make install
```

If `bettercap` is **not** available in your distribution's repositories, install bettercap v2
from the upstream release (a Go build of `bettercap`, **not** the old `gem install bettercap`),
then re-run the installer. `install.py` prints guidance when `bettercap` cannot be found.

---

## Usage

```bash
sudo xerosploit
```

Navigate the interactive menu by typing an option name and pressing Enter. Inside a module,
type `run` to execute, `back` to return, `home` to go back to the start, or `exit` to quit.

The tool works both from the git checkout and from the installed `/opt/xerosploit` location
(paths are resolved relative to the running script, so no hardcoded absolute path is needed).

### Choosing targets

Type a single target IP (e.g. `192.168.1.10`) or a comma-separated list
(`192.168.1.10,192.168.1.11`). The `all` command targets the whole network: Xerosploit-NG
expands it to the live neighbours seen on the selected interface (minus your own address and
the default gateway), and falls back to the interface's IPv4 network in CIDR form
(e.g. `192.168.1.0/24`) when the neighbour table is empty. This produces a real
`arp.spoof.targets` value, avoiding bettercap's "list of targets is empty, module not
starting" silent no-op.

### Sniff prompts and output

The **Sniff** module asks two questions in order — `Do you want to save logs ? (y/n).` then
`Do you want to load sslstrip ? (y/n).`. When you answer `y` to sslstrip, a third prompt
appears: `Enable full HTTPS interception (needs bettercap CA on the victim)? [y/N]` — the
default is `n`, and `https.proxy on` is added only when you answer `y`.

Sniffing output is written to `xerosniff/` in the repo root: a `<target>_<date>.pcap` capture
plus the matching `<target>_<date>.log` event stream, and the run prints
`All logs are saved on : <xerosniff path>`. The scanning modules (Scan, Port scanning, Ping)
keep their plain-text logs separately, under `tools/log/` (`scan.txt`, `pscan.txt`, `ping.txt`).

### Features

- Port scanning (nmap)
- Network mapping (nmap)
- DoS attack (hping3)
- Traffic sniffing (bettercap `net.sniff`)
- SSL strip (bettercap `http.proxy` / `https.proxy`)
- DNS spoofing (bettercap `dns.spoof`)
- HTML code injection
- JavaScript code injection
- Shake screen
- Download interception and replacement
- Images replacement
- YouTube "rickroll" hijack
- Webpage defacement
- Driftnet image sniffing

### Menu → module mapping

| Menu entry | bettercap v2 module |
|---|---|
| Inject HTML | `modules/injecthtml.js` |
| Javascript injection | `modules/injectjs.js` (via `http.proxy.script`; not bettercap's built-in `injectjs`) |
| Shake screen | `modules/shakescreen.js` |
| Replace Download | `modules/replace_file.js` |
| Image Replace | `modules/replace_images.js` |
| YouTube Play | `modules/rickroll.js` |
| Deface Web Page | `modules/deface.js` |

The `modules/*.js` files are bettercap v2 HTTP-proxy scripts. Their parameters are supplied
through generated `XE_*` globals so nothing is hardcoded, and each module is a strict
passthrough for traffic it is not meant to touch.

The content-injection modules (Inject HTML, Deface, Inject JS, Replace Download, Replace
Images) ask for a **local file path** at prompt time; `tools/files/` is the conventional place
to keep those input files.

---

## HTTPS, HSTS and Content-Security-Policy notes

### Plain HTTP works out of the box

HTML/JavaScript injection, image replacement and defacement only work on plain **HTTP** by
default, because HTTPS bodies are encrypted end-to-end between the victim and the server.

### Full HTTPS interception is opt-in

When you enable `sslstrip` in the **Sniff** module, Xerosploit-NG only turns on
`http.proxy.sslstrip` (the HTTP downgrade). It does **not** silently start `https.proxy`,
because doing so breaks HTTPS for any client that does not trust bettercap's CA. Full TLS
interception is asked for explicitly
(`Enable full HTTPS interception (needs bettercap CA on the victim)? [y/N]`) and adds
`https.proxy on` only when you answer `y`.

To make full HTTPS interception work you must:

1. Answer `y` to the full-HTTPS prompt (or add `https.proxy on` yourself).
2. **Install bettercap's CA certificate on the victim device** and mark it trusted. bettercap
   generates the CA on first use (by default `~/.bettercap-ca.crt`); until the victim trusts
   it, the browser will reject the forged certificates and the injection will not be applied.

Limits to keep in mind:

- **HSTS / preload:** sites served with `Strict-Transport-Security` (especially those on the
  browser HSTS preload list) refuse the downgrade to HTTP for the lifetime of the policy, so
  sslstrip alone cannot strip them.
- **No CA installed:** HTTPS pages remain opaque to the proxy; only SNI/DNS metadata is
  visible.
- **Certificate pinning / QUIC:** pinned apps and HTTP/3 (QUIC) traffic may bypass or reject
  the proxy entirely.

### Content-Security-Policy

Even on plain HTTP, injected inline JavaScript and iframes are frequently blocked by a site's
Content-Security-Policy (`script-src` / `frame-src`), so an injection may have no visible
effect on hardened pages.

---

## Demonstration

https://www.youtube.com/watch?v=35QUrtZEV9U

---

## License

Xerosploit-NG is free software, released under the **GNU General Public License v3 (GPLv3)**.
See [LICENSE](LICENSE) for the full text.

## Credits

- **LionSec** — original Xerosploit author (https://github.com/LionSec/xerosploit, https://lionsec.net)
- **Neodrix** — Xerosploit fork and maintainer (https://github.com/Neodrix/Xerosploit, https://neodrix.com)
- **Simone 'evilsocket' Margaritelli** — bettercap, and the original v1 Ruby proxy modules
  that the `modules/*.js` files are ported from

### Contact

- Website: https://neodrix.com
- Issues: https://github.com/LionSec/xerosploit/issues
- YouTube: https://youtube.com/inf98es
- Facebook: https://facebook.com/in98
- Twitter: @LionSec1
- Email: informatic98es@gmail.com

### Donations

- Paypal: https://www.paypal.me/lionsec
- Bitcoin: 12dM5kZjYMizNuXaqu7QZBLNDkXjfKYpRD
