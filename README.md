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

**Xerosploit-NG** revives the original project on modern Linux: the outdated bundled
**bettercap v1 (Ruby, `xettercap`)** has been removed and replaced by **bettercap v2 (Go)**,
and the menu/UX has been ported to **Python 3**. It is powered by
[bettercap](https://www.bettercap.org) and [nmap](https://nmap.org).

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
- **tabulate** and **terminaltables** (Python libraries used by the menu)

No other dependencies are required.

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

```bash
git clone https://github.com/LionSec/xerosploit
cd xerosploit
sudo python3 install.py
```

The installer installs the dependencies, copies the tree to `/opt/xerosploit`, and installs
the `xerosploit` launcher into `/usr/bin`.

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
| Javascript injection | bettercap built-in `http.proxy.injectjs` (and `modules/injectjs.js`) |
| Shake screen | `modules/shakescreen.js` |
| Replace Download | `modules/replace_file.js` |
| Image Replace | `modules/replace_images.js` |
| YouTube Play | `modules/rickroll.js` |
| Deface Web Page | `modules/deface.js` |

The `modules/*.js` files are bettercap v2 HTTP-proxy scripts. Their parameters are supplied
through generated `XE_*` globals so nothing is hardcoded, and each module is a strict
passthrough for traffic it is not meant to touch.

---

## HTTPS note

HTML/JavaScript injection, image replacement and defacement only work on plain **HTTP** by
default, because HTTPS bodies are encrypted end-to-end between the victim and the server.

To apply them over **HTTPS** you must:

1. Enable bettercap's HTTPS proxy (`https.proxy on`, optionally with `sslstrip`).
2. **Install bettercap's CA certificate on the victim device** and mark it trusted. bettercap
   generates the CA on first use (by default `~/.bettercap-ca.crt`); until the victim trusts
   it, the browser will reject the forged certificates and the injection will not be applied.

Without the CA installed on the victim, HTTPS pages remain opaque to the proxy.

---

## Demonstration

https://www.youtube.com/watch?v=35QUrtZEV9U

---

## License

Xerosploit-NG is free software, released under the **GNU General Public License v3 (GPLv3)**.
See [LICENSE](LICENSE) for the full text.

## Credits

- **LionSec** — original Xerosploit author (https://lionsec.net)
- **Neodrix** — Xerosploit maintainer (https://neodrix.com)
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
