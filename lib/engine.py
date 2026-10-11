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

import json
import os
import shutil
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
    return os.path.abspath(os.path.join(MODULES_DIR, module_file))


# ------------------------------------------------------------------------- #
# Helpers
# ------------------------------------------------------------------------- #

def _targets_str(targets):
    if isinstance(targets, (list, tuple, set)):
        return ",".join(str(t) for t in targets)
    return str(targets)


def _js_literal(value):
    """Render a python value as a JavaScript literal (strings, lists, bools)."""
    return json.dumps(value)


def _param_global(name):
    return "XE_" + str(name).upper()


# ------------------------------------------------------------------------- #
# bettercap v2 command builders -> list[str] of session commands
# ------------------------------------------------------------------------- #

def arp_spoof(targets, internal=True, fullduplex=True):
    """ARP spoofing commands.  targets empty/None means the whole subnet."""
    cmds = []
    if targets:
        cmds.append("set arp.spoof.targets " + _targets_str(targets))
    if internal:
        cmds.append("set arp.spoof.internal true")
    cmds.append("set arp.spoof.fullduplex " + ("true" if fullduplex else "false"))
    cmds.append("arp.spoof on")
    return cmds


def http_proxy(script=None, injectjs=None, port=8080, sslstrip=False, address=None):
    """HTTP proxy commands.  `script` is an absolute JS module path and
    `injectjs` is a file path or raw JavaScript payload (bettercap built-in)."""
    cmds = []
    if port is not None:
        cmds.append("set http.proxy.port %d" % int(port))
    if address:
        cmds.append("set http.proxy.address " + str(address))
    if sslstrip:
        cmds.append("set http.proxy.sslstrip true")
    if script:
        cmds.append("set http.proxy.script " + str(script))
    if injectjs:
        cmds.append("set http.proxy.injectjs " + str(injectjs))
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
        cmds.append("set net.sniff.output " + str(output))
    cmds.append("set net.sniff.local " + ("true" if local else "false"))
    cmds.append("set net.sniff.verbose " + ("true" if verbose else "false"))
    cmds.append("net.sniff on")
    return cmds


def dns_spoof(domains, address):
    """DNS spoofing commands redirecting `domains` to `address`."""
    cmds = []
    if domains:
        joined = _targets_str(domains)
        if joined.strip() == "*":
            # "*" means every domain: bettercap v2 uses dns.spoof.all for that.
            cmds.append("set dns.spoof.all true")
        else:
            cmds.append("set dns.spoof.domains " + joined)
            if "*" in joined:
                cmds.append("set dns.spoof.all true")
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
# Runner
# ------------------------------------------------------------------------- #

def run(iface, commands, logfile=None, caplet=None, extra_eval=None):
    """Launch one bettercap session and block until it exits.

    Composes `bettercap -iface <iface> [-caplet <file>] -eval "<cmd; cmd; ...>"`
    and uses subprocess.call so that Ctrl+C reaches bettercap through the shared
    foreground process group (letting it restore the ARP cache).  Returns the
    bettercap exit code.

    `logfile` is honoured through bettercap's event stream (`events.stream.output`)
    because bettercap v2 has no `-log` command line flag (see core/options.go).
    """
    argv = [bettercap_bin()]
    if iface:
        argv += ["-iface", str(iface)]

    session_commands = list(commands or [])
    if extra_eval:
        session_commands.append(extra_eval)
    if logfile:
        # bettercap v2 has no -log flag; redirect the event stream to the file
        # instead (modules/events_stream: events.stream.output).  The UI tails it.
        session_commands.append("set events.stream.output " + str(logfile))
        session_commands.append("events.stream on")
    if caplet:
        argv += ["-caplet", str(caplet)]
    if session_commands:
        argv += ["-eval", "; ".join(session_commands)]

    sys.stdout.flush()
    sys.stderr.flush()
    try:
        return subprocess.call(argv)
    except KeyboardInterrupt:
        # Ctrl+C is delivered to bettercap too (same foreground process group),
        # so it can restore the ARP cache before exiting.
        return 130
