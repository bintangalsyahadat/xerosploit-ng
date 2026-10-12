# Xerosploit-NG — Kali Live test runbook

How to validate the revived Xerosploit on a modern Kali (Live USB) against a real LAN victim.
This is a self-run checklist; the tool has only been statically verified off-Kali so far.

## 0. What changed (context)

* Python 3 only; the bundled bettercap v1 (`xettercap`, Ruby) is gone.
* All MITM/injection now runs on **bettercap v2 (Go)** via `lib/engine.py`.
* `modules/*.js` are bettercap v2 proxy scripts; params are injected as `XE_*` globals.
* Repo: `xerosploit-ng/` (local). No git remote yet.

## 1. Get the code onto Kali

The dev repo lives on the Mint machine. Easiest transfer to a Kali Live session:

```bash
# on Mint: copy the repo to the Ventoy exfat partition
cp -r ~/Documents/opencode/xerosploit-ng /media/bintang/Ventoy/
sync
```

```bash
# in Kali Live: copy it off the USB to a writable place and check what you got
ls /media/kali/Ventoy/            # find the Ventoy partition device/label
cp -r /media/kali/Ventoy/xerosploit-ng ~/xerosploit-ng
cd ~/xerosploit-ng
```

(If you set up a git remote later, `git clone` is equivalent.)

## 2. Install

```bash
sudo apt-get update
sudo apt-get install -y bettercap nmap hping3 driftnet
sudo python3 install.py          # copies to /opt/xerosploit, launcher /usr/bin/xerosploit
```

`install.py` is only needed for the `/opt/xerosploit` + `/usr/bin/xerosploit` install. You can
also run directly from the checkout (no install step):

```bash
sudo python3 xerosploit.py
```

Sanity checks:

```bash
bettercap -version               # must print a 2.x version
python3 -m py_compile /opt/xerosploit/xerosploit.py /opt/xerosploit/lib/engine.py
```

## 3. Recon, then smoke-test each module

```bash
ip -4 addr ; ip route           # find the Wi-Fi iface name + your IP (Kali usually wlan0)
sudo ip link set <iface> up
# find the victim (e.g. the Redmi)
nmap -sn 192.168.1.0/24
ip neigh show dev <iface>
```

Run:

```bash
sudo xerosploit
```

Then, per module, confirm the expected effect on the victim device:

| Menu module | How to run | Expected evidence |
|---|---|---|
| Scan / Port scanning | pick target | nmap output |
| Sniff | run, choose logs y/n, sslstrip n | captured HTTP creds in the tailed log + `xerosniff/<target>_<date>.pcap` (with the matching `.log`) |
| Sniff + sslstrip | sslstrip y (answer the full-HTTPS prompt n) | same, plus HTTP downgrade attempts |
| Dns spoof | give redirect IP (e.g. your IP) | victim's DNS names resolve to that IP |
| Inject Html | point at a local .html | injected markup on victim pages (HTTP) |
| Deface | point at a local .html | whole page replaced (HTTP) |
| Inject Js | point at a .js | JS runs in victim pages (HTTP) |
| Shake screen | run | victim page shakes |
| Download spoof | give extension + file | download replaced (HTTP) |
| Replace images | give an image | images swapped (HTTP) |
| Youtube hijack | give a video id | victim YouTube loads the rickroll iframe |
| Driftnet | run | driftnet window shows images |

Demo target for creds: `http://testphp.vulnweb.com/login.php` (login `test`/`test`), then check the pcap in Wireshark (`http.request.method == "POST"`).

## 4. Things to validate explicitly (known v2 API uncertainties)

These are assumptions in the port that only a live bettercap run can confirm:

1. **`res.ReadBody()` / `res.Body`** semantics in bettercap v2 proxy scripts — the JS modules read the body with `res.ReadBody()` and write back `res.Body`. Confirm an HTML page really gets modified.
2. **`modules/injectjs.js` / `modules/shakescreen.js`** loaded via `set http.proxy.script`
   (bettercap's built-in `http.proxy.injectjs` is no longer used: it consumes the response
   body and only restores it on an exact lowercase `</head>`, so it can return empty/broken
   pages).
3. **`dns.spoof.all true`** for the "all domains" case (Dns spoof passes `["*"]`).
4. **`set events.stream.output <file>`** is how the log file is produced (bettercap v2 has **no `-log` flag**); confirm the tailed log fills up.
5. **HTTPS injection** requires bettercap's CA installed on the victim; without it HTTPS stays unreadable (only SNI/DNS). `https.proxy` is now opt-in (the Sniff module asks before enabling it). HSTS/preload sites and certificate-pinned apps/QUIC resist sslstrip and the forged CA regardless.

## 5. Cleanup (after each run)

Stop bettercap with `Ctrl+C` (it restores the ARP cache). Then verify on the victim that connectivity recovered, and:

```bash
ip neigh show dev <iface>
```

## 6. If a module misbehaves

Capture the exact `bettercap` command engine built:

```bash
python3 - <<'PY'
import sys; sys.path.insert(0, "lib"); import engine
print(engine.arp_spoof(["192.168.1.4"]))
print(engine.http_proxy(script=engine.script("injecthtml.js")))
PY
```

Then run that command manually and read bettercap's error (unknown parameter, missing script, etc.).
