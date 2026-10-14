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

"""Xerosploit-NG static self-test.

Repeatable checks that need neither root nor bettercap:

* ``py_compile`` every ``.py`` file (byte-compiled into a temp directory so the
  repo is left untouched);
* AST-parse every ``.py`` file;
* ``node --check`` every ``modules/*.js`` (skipped with a warning when node is
  missing; a missing node is not a failure);
* assert the ``lib/engine.py`` command builders compose the expected bettercap
  v2 session commands, and that ``write_runtime_module`` renders a module body
  plus its ``XE_*`` globals into a temporary directory (never ``tools/tmp``).

Prints a PASS/FAIL summary and exits non-zero on any failure.
"""

import ast
import os
import py_compile
import shutil
import subprocess
import sys
import tempfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "lib"))

import engine  # noqa: E402

FAILURES = []
SKIPS = []


def ok():
    print("\033[1;32m[PASS]\033[1;m")


def fail(message):
    print("\033[1;31m[FAIL]\033[1;m " + message)
    FAILURES.append(message)


def section(title):
    print("\n\033[1;36m=== " + title + " ===\033[1;m")


# ------------------------------------------------------------------------- #
# Discovery
# ------------------------------------------------------------------------- #

def iter_py_files():
    """Every .py file, excluding __pycache__ and tools/tmp (generated code)."""
    for root, dirs, files in os.walk(BASE_DIR):
        rel = os.path.relpath(root, BASE_DIR).replace(os.sep, "/")
        if rel == "tools/tmp" or rel.startswith("tools/tmp/"):
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
        for name in sorted(files):
            if name.endswith(".py"):
                yield os.path.join(root, name)


def iter_js_modules():
    modules_dir = os.path.join(BASE_DIR, "modules")
    if not os.path.isdir(modules_dir):
        return
    for name in sorted(os.listdir(modules_dir)):
        if name.endswith(".js"):
            yield os.path.join(modules_dir, name)


# ------------------------------------------------------------------------- #
# Checks
# ------------------------------------------------------------------------- #

def check_py_compile(py_files, scratch):
    section("py_compile")
    count = 0
    for path in py_files:
        rel = os.path.relpath(path, BASE_DIR)
        cfile = os.path.join(scratch, rel.replace(os.sep, "_") + "c")
        try:
            py_compile.compile(path, cfile=cfile, doraise=True)
        except py_compile.PyCompileError as exc:
            fail("py_compile %s: %s" % (rel, exc))
        except Exception as exc:  # noqa: BLE001 - report anything unexpected
            fail("py_compile %s: %r" % (rel, exc))
        else:
            count += 1
    if not FAILURES:
        ok()
    print("  compiled %d .py file(s)" % count)


def check_ast(py_files):
    section("AST parse")
    count = 0
    errors_before = len(FAILURES)
    for path in py_files:
        rel = os.path.relpath(path, BASE_DIR)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                ast.parse(fh.read(), filename=path)
        except SyntaxError as exc:
            fail("AST parse %s: %s" % (rel, exc))
        except Exception as exc:  # noqa: BLE001
            fail("AST parse %s: %r" % (rel, exc))
        else:
            count += 1
    if len(FAILURES) == errors_before:
        ok()
    print("  parsed %d .py file(s)" % count)


def check_node(js_files):
    section("node --check (modules/*.js)")
    node = shutil.which("node")
    if node is None:
        message = "node not found in PATH; skipping JS syntax checks"
        print("\033[1;33m[WARN]\033[1;m " + message)
        SKIPS.append(message)
        return
    count = 0
    errors_before = len(FAILURES)
    for path in js_files:
        rel = os.path.relpath(path, BASE_DIR)
        proc = subprocess.run(
            [node, "--check", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode != 0:
            fail("node --check %s:\n%s" % (rel, proc.stderr.decode("utf-8", "replace").strip()))
        else:
            count += 1
    if len(FAILURES) == errors_before:
        ok()
    print("  checked %d .js file(s) with %s" % (count, node))


def _command_problems(cmds, must_contain=()):
    """Return a list of problems for a builder's command list, or [] if fine."""
    problems = []
    if not isinstance(cmds, list) or not cmds:
        return ["not a non-empty list"]
    if not all(isinstance(c, str) for c in cmds):
        problems.append("contains a non-string entry")
    if not any(c.startswith("set ") for c in cmds):
        problems.append("no 'set ...' command")
    if not any(c.endswith(" on") for c in cmds):
        problems.append("no '... on' command")
    for token in must_contain:
        if not any(token in c for c in cmds):
            problems.append("missing %r" % token)
    return problems


def _order_problems(cmds, ordered):
    """Return problems unless every `ordered` token appears in that order.

    Ordering matters for arp_spoof: net.probe must be enabled before arp.spoof
    starts, or bettercap cannot resolve the target MAC and spoofs nothing.
    """
    positions = []
    for token in ordered:
        hit = next((i for i, c in enumerate(cmds) if token in c), None)
        if hit is None:
            return ["missing %r" % token]
        positions.append(hit)
    if positions != sorted(positions):
        return ["wrong order for %r" % (ordered,)]
    return []


def check_engine_composition():
    section("engine composition")
    builders = [
        ("arp_spoof", lambda: engine.arp_spoof(["1.2.3.4"]),
         ("set arp.spoof.targets 1.2.3.4", "net.probe on", "arp.spoof on"),
         ("net.probe on", "arp.spoof on")),
        ("http_proxy", lambda: engine.http_proxy(),
         ("set http.proxy.port 8080", "http.proxy on"), ()),
        ("net_sniff", lambda: engine.net_sniff(output="/tmp/x.pcap"),
         ("set net.sniff.output /tmp/x.pcap", "net.sniff on"), ()),
        ("dns_spoof", lambda: engine.dns_spoof(["*"], "1.2.3.4"),
         ("set dns.spoof.address 1.2.3.4", "dns.spoof on"), ()),
    ]
    for name, factory, must_contain, ordered in builders:
        try:
            cmds = factory()
        except Exception as exc:  # noqa: BLE001
            fail("engine.%s() raised %r" % (name, exc))
            continue
        problems = _command_problems(cmds, must_contain)
        problems += _order_problems(cmds, ordered)
        if problems:
            fail("engine.%s(): %s (%r)" % (name, "; ".join(problems), cmds))
        else:
            ok()
            print("  engine.%s() -> %r" % (name, cmds))


def check_engine_validation():
    section("engine validation (empty targets, -eval injection guards)")
    cases = [
        ("arp_spoof([])", lambda: engine.arp_spoof([])),
        ("arp_spoof(None)", lambda: engine.arp_spoof(None)),
        ("arp_spoof(['1.2.3.4; rm -rf /'])",
         lambda: engine.arp_spoof(["1.2.3.4; rm -rf /"])),
        ("http_proxy(address='a;b')", lambda: engine.http_proxy(address="a;b")),
        ("dns_spoof(['*'], '1.2.3.4\\n')",
         lambda: engine.dns_spoof(["*"], "1.2.3.4\n")),
    ]
    for name, factory in cases:
        try:
            factory()
        except engine.EngineError:
            ok()
            print("  %s -> EngineError (expected)" % name)
        except Exception as exc:  # noqa: BLE001
            fail("%s raised %r, expected EngineError" % (name, exc))
        else:
            fail("%s did not raise" % name)

    # http_proxy must not use bettercap's built-in injectjs anymore.
    try:
        cmds = engine.http_proxy(script="/tmp/mod.js")
    except Exception as exc:  # noqa: BLE001
        fail("http_proxy(script=...) raised %r" % (exc,))
    else:
        if any("injectjs" in c for c in cmds):
            fail("http_proxy still emits http.proxy.injectjs: %r" % (cmds,))
        else:
            ok()
            print("  http_proxy(script=...) -> %r" % (cmds,))


def check_write_runtime_module():
    section("write_runtime_module (temp dirs, no tools/tmp pollution)")
    src_module = os.path.join(BASE_DIR, "modules", "rickroll.js")
    if not os.path.isfile(src_module):
        fail("modules/rickroll.js is missing")
        return

    with tempfile.TemporaryDirectory() as tmp:
        mod_dir = os.path.join(tmp, "modules")
        tmp_dir = os.path.join(tmp, "tmp")
        os.makedirs(mod_dir)
        shutil.copy2(src_module, os.path.join(mod_dir, "rickroll.js"))

        saved_modules, saved_tmp = engine.MODULES_DIR, engine.TMP_DIR
        engine.MODULES_DIR, engine.TMP_DIR = mod_dir, tmp_dir
        try:
            out_path = engine.write_runtime_module("rickroll.js", {"video_id": "abc"})
        except Exception as exc:  # noqa: BLE001
            fail("write_runtime_module raised %r" % (exc,))
            return
        finally:
            engine.MODULES_DIR, engine.TMP_DIR = saved_modules, saved_tmp

        with open(out_path, "r", encoding="utf-8") as fh:
            content = fh.read()
        with open(os.path.join(mod_dir, "rickroll.js"), "r", encoding="utf-8") as fh:
            body = fh.read()

        problems = []
        if not os.path.abspath(out_path).startswith(os.path.abspath(tmp_dir)):
            problems.append("output written outside the temp TMP_DIR (%s)" % out_path)
        if "XE_VIDEO_ID" not in content:
            problems.append("missing XE_VIDEO_ID global")
        if '"abc"' not in content:
            problems.append("missing the video_id value")
        if body.strip() and body.strip() not in content:
            problems.append("module body not embedded")

        if problems:
            fail("write_runtime_module: " + "; ".join(problems))
        else:
            ok()
            print("  wrote %s" % out_path)


def check_sniffer_helpers():
    section("packet sniffer helpers (bpf filter and discovery)")
    cases = [
        ("single host", "192.168.1.10", "host 192.168.1.10"),
        ("subnet CIDR", "192.168.1.0/24", "net 192.168.1.0/24"),
        ("comma hosts", "192.168.1.1, 192.168.1.2", "host 192.168.1.1 or host 192.168.1.2"),
        ("list mixed", ["10.0.0.1", "172.16.0.0/16"], "host 10.0.0.1 or net 172.16.0.0/16"),
        ("empty/none", None, ""),
    ]
    for label, target, expected in cases:
        bpf = engine.build_bpf_filter(target)
        if bpf != expected:
            fail("build_bpf_filter(%r) -> %r, expected %r" % (target, bpf, expected))
        else:
            ok()
            print("  build_bpf_filter(%s) -> %r" % (label, bpf))

    name, path = engine.sniffer_bin()
    if name:
        ok()
        print("  found sniffer: %s at %s" % (name, path))
    else:
        SKIPS.append("neither tcpdump nor dumpcap found in PATH")



# ------------------------------------------------------------------------- #
# Entry point
# ------------------------------------------------------------------------- #

def main():
    py_files = list(iter_py_files())
    js_files = list(iter_js_modules())

    print("\033[1;36mXerosploit-NG self-test\033[1;m")
    print("  base dir : %s" % BASE_DIR)
    print("  python   : %s" % sys.version.split()[0])
    print("  .py files: %d" % len(py_files))
    print("  .js files: %d" % len(js_files))

    with tempfile.TemporaryDirectory() as scratch:
        check_py_compile(py_files, scratch)
    check_ast(py_files)
    check_node(js_files)
    check_engine_composition()
    check_engine_validation()
    check_write_runtime_module()
    check_sniffer_helpers()

    section("summary")
    for message in SKIPS:
        print("\033[1;33m[WARN]\033[1;m " + message)
    if FAILURES:
        print("\033[1;31mFAILED\033[1;m - %d problem(s):" % len(FAILURES))
        for message in FAILURES:
            print("  - " + message)
        return 1
    print("\033[1;32mPASS\033[1;m - all checks succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
