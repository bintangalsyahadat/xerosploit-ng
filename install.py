#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import shutil
import subprocess
import sys

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
#        Copyright © 2016 LionSec (www.lionsec.net)                         #
#                                                                           #
#---------------------------------------------------------------------------#

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTALL_DIR = "/opt/xerosploit"
LAUNCHER = "/usr/bin/xerosploit"

if not os.geteuid() == 0:
    sys.exit("""\033[1;91m\n[!] Xerosploit installer must be run as root. ¯\_(ツ)_/¯\n\033[1;m""")

print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                     Xerosploit Installer                     █
█                                                              █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")


def run_shell(command):
    print("\033[1;34m\n[++] " + command + "\033[1;m")
    return subprocess.call(command, shell=True)


def have(program):
    return shutil.which(program) is not None


def install_packages():
    """apt family installer: Kali, Parrot OS, Ubuntu and Debian."""
    if not have("apt-get"):
        sys.exit(
            "\033[1;91m\n[!] This installer only supports apt-based distributions "
            "(Kali, Parrot OS, Ubuntu, Debian).\033[1;m"
        )

    run_shell("apt-get update")
    run_shell("apt-get install -y bettercap nmap hping3 driftnet python3-pip")


def python_deps_available():
    """True when tabulate and terminaltables can actually be imported."""
    return subprocess.call(
        [sys.executable or "python3", "-c", "import tabulate, terminaltables"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) == 0


def install_python_deps():
    """Prefer the distro packages for tabulate/terminaltables, fall back to pip3.

    These libraries are cosmetic only: xerosploit.py falls back to a built-in
    table renderer when they are missing, so a failure here is non-fatal.
    """
    rc = run_shell("apt-get install -y python3-tabulate python3-terminaltables")
    if rc != 0:
        print("\033[1;33m\n[!] apt packages unavailable, falling back to pip3.\033[1;m")
        rc = run_shell("pip3 install --break-system-packages tabulate terminaltables")
    if rc != 0 or not python_deps_available():
        print("\033[1;33m\n[!] Could not install tabulate/terminaltables; "
              "Xerosploit will use its built-in table renderer instead "
              "(non-fatal).\033[1;m")


def copy_tree():
    """Copy the tool to /opt/xerosploit.

    tools/bettercap/ (the old bettercap v1 Ruby engine) is intentionally NOT
    copied: Xerosploit-NG drives bettercap v2 (Go) through lib/engine.py.
    """
    if os.path.isdir(INSTALL_DIR):
        shutil.rmtree(INSTALL_DIR)

    os.makedirs(os.path.join(INSTALL_DIR, "tools", "files"), exist_ok=True)
    os.makedirs(os.path.join(INSTALL_DIR, "tools", "log"), exist_ok=True)
    os.makedirs(os.path.join(INSTALL_DIR, "tools", "tmp"), exist_ok=True)

    for name in ("xerosploit.py", "banner.py", "install.py", "LICENSE",
                 "Makefile", "README.md", "run.sh"):
        src = os.path.join(BASE_DIR, name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(INSTALL_DIR, name))

    # lib/ (bettercap v2 engine) and modules/ (proxy JS modules).
    for directory in ("lib", "modules"):
        src = os.path.join(BASE_DIR, directory)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(INSTALL_DIR, directory), dirs_exist_ok=True)

    # tools/files, tools/log, tools/tmp only -- never tools/bettercap.
    for directory in ("files", "log", "tmp"):
        src = os.path.join(BASE_DIR, "tools", directory)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(INSTALL_DIR, "tools", directory), dirs_exist_ok=True)

    if os.path.exists(LAUNCHER):
        os.remove(LAUNCHER)
    shutil.copy2(os.path.join(BASE_DIR, "run.sh"), LAUNCHER)
    os.chmod(LAUNCHER, 0o755)


def main():
    print("\033[1;34m\n[++] Installing Xerosploit ... \033[1;m")

    install_packages()
    install_python_deps()
    copy_tree()

    if not have("bettercap"):
        print("""\033[1;91m
[!] bettercap v2 was not found after installation.
    Some distributions do not ship bettercap v2 in their repositories.
    Install it manually, for example:
      Kali Linux : sudo apt-get install bettercap
      Parrot OS  : sudo apt-get install bettercap
    Or build it from source: https://github.com/bettercap/bettercap
\033[1;m""")

    print("\033[1;32m\n[++] Xerosploit has been successfully installed. "
          "Execute 'xerosploit' in your terminal.\033[1;m")


if __name__ == "__main__":
    main()
