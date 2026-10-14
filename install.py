#!/usr/bin/env python3
"""Trawler installer — multi-platform (apt / brew / choco), idempotent.

Installs Wireshark CLI tools (tshark, editcap, capinfos) which are the
core dependencies. Python deps are stdlib-only for v1, so requirements.txt
is empty / minimal.
"""
import subprocess, sys, os, shutil
from pathlib import Path

TOOL_NAME  = "Trawler"
MIN_PYTHON = (3, 10)

def _run(cmd, check=True):
    print(f"  → {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check)

def _has(binary): return shutil.which(binary) is not None



def _dpkg_installed(pkg):
    try:
        r = subprocess.run(["dpkg", "-s", pkg],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def _rpm_installed(pkg):
    try:
        return subprocess.run(
            ["rpm", "-q", pkg],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0
    except FileNotFoundError:
        return False


def _pip_installed(pkg_spec):
    """Check whether a pip package is already importable."""
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "python-whois": "whois", "beautifulsoup4": "bs4", "python-docx": "docx",
        "pyOpenSSL": "OpenSSL", "dnspython": "dns", "pyyaml": "yaml",
        "Pillow": "PIL", "charset-normalizer": "charset_normalizer",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    try:
        return importlib.util.find_spec(mod) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def install_system_deps():
    """tshark / editcap / capinfos / dumpcap via OS package manager."""
    needed = {
        "tshark":   "wireshark-common",   # Debian/Ubuntu/Kali ships tshark in wireshark-common
        "editcap":  "wireshark-common",
        "capinfos": "wireshark-common",
    }
    pkgs_to_install = set()
    for binary, pkg in needed.items():
        if not _has(binary):
            pkgs_to_install.add(pkg)
            print(f"  [need] {binary} not on PATH → install package: {pkg}")
        else:
            print(f"  [ok]   {binary} already installed at {shutil.which(binary)}")

    if not pkgs_to_install:
        return

    if sys.platform.startswith("linux") and _has("apt-get"):
        _run(["apt-get", "update"], check=False)
        _all_pkgs = list(pkgs_to_install)
        _needed = [p for p in _all_pkgs if not _dpkg_installed(p)]
        if len(_needed) < len(_all_pkgs):
            print(f"  {len(_all_pkgs) - len(_needed)} APT package(s) already installed")
        if _needed:
            _run(["apt-get", "install", "-y"] + _needed)
        else:
            print("  ✓ All APT packages already installed")
    elif sys.platform == "darwin" and _has("brew"):
        _run(["brew", "install", "wireshark"])
    elif _has("choco"):
        _run(["choco", "install", "-y", "wireshark"])
    elif _has("dnf"):
        _run(["dnf", "install", "-y", "wireshark-cli"])
    elif _has("yum"):
        _run(["yum", "install", "-y", "wireshark"])
    elif _has("pacman"):
        _run(["pacman", "-S", "--noconfirm", "wireshark-cli"])
    else:
        print(f"  [!]  No supported package manager found; install Wireshark "
              f"CLI tools manually.\n      Required binaries: {', '.join(needed)}")
        sys.exit(1)

def install_python_deps():
    """Install Python deps from requirements.txt, checking each first."""
    req = Path(__file__).parent / "requirements.txt"
    if not req.exists() or not req.read_text().strip():
        print("  [ok] no Python deps required (stdlib-only)")
        return
    pip = [sys.executable, "-m", "pip"]
    for line in req.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if _pip_installed(line):
            print(f"  [ok]   ✓ {line} already installed")
            continue
        print(f"  [*] pip install {line} …")
        try:
            _run(pip + ["install", "--break-system-packages", line])
        except subprocess.CalledProcessError:
            print(f"  [!] pip install failed for {line}")

def create_dirs():
    """Trawler keeps no global state; clients/run-dirs are created per scan
    in the universal layout. Nothing to do here."""
    print("  [ok] no global directories required (per-scan layout)")

def init_auth():
    """Trawler is a CLI tool (no web UI), so _auth.py initialisation is
    not required."""
    print("  [ok] no auth bootstrap required (CLI tool)")

def main():
    if sys.version_info < MIN_PYTHON:
        print(f"ERROR: Python {'.'.join(map(str, MIN_PYTHON))}+ required, "
              f"have {sys.version}")
        sys.exit(1)

    print(f"{TOOL_NAME} — Installation")
    print("=" * 56)
    print()
    print("[1/4] System dependencies (Wireshark CLI tools)…")
    install_system_deps()
    print()
    print("[2/4] Python dependencies…")
    install_python_deps()
    print()
    print("[3/4] Directories…")
    create_dirs()
    print()
    print("[4/4] Auth bootstrap…")
    init_auth()
    print()
    print(f"{TOOL_NAME} installed.")
    print()
    print("Quick start:")
    print(f"  {sys.executable} trawler.py \\")
    print(f"    --pcap /path/to/capture.pcapng \\")
    print(f"    --target 192.168.1.150 \\")
    print(f"    --include-internal \\")
    print(f"    --scope int \\")
    print(f"    --output-dir /clients/<client>/2026/trawler/<client>_$(date +%Y%m%d_%H%M%S)/ \\")
    print(f"    --client <client>")

if __name__ == "__main__":
    main()
