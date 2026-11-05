#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClawProbe Desktop — Windows 10/11 (x64) Single-File Executable Packaging Script (`build_windows_exe.py`)

Builds `dist/ClawProbe-Desktop-Win64.exe` from the open-source `clawprobe_desktop.py` GUI reference demo
using PyInstaller, and emits its SHA-256 verification sidecar (`ClawProbe-Desktop-Win64.exe.sha256`).
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
SRC_DIR = REPO_ROOT / "src"
DESKTOP_SCRIPT = ROOT / "clawprobe_desktop.py"
DIST_DIR = ROOT / "dist"


def build_win64_executable() -> dict[str, str]:
    if not DESKTOP_SCRIPT.exists():
        raise FileNotFoundError(f"Missing desktop script: {DESKTOP_SCRIPT}")

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name",
        "ClawProbe-Desktop-Win64",
        "--distpath",
        str(DIST_DIR),
    ]
    if SRC_DIR.exists():
        cmd.extend(["--paths", str(SRC_DIR)])
    cmd.append(str(DESKTOP_SCRIPT))

    res = subprocess.run(cmd, check=False)
    if res.returncode != 0:
        raise RuntimeError(
            "PyInstaller build failed. Ensure PyInstaller is installed (`pip install pyinstaller`) on Windows x64."
        )

    exe_path = DIST_DIR / ("ClawProbe-Desktop-Win64.exe" if sys.platform == "win32" else "ClawProbe-Desktop-Win64")
    if not exe_path.exists():
        raise FileNotFoundError(f"Expected output binary not found: {exe_path}")

    sha256_hex = hashlib.sha256(exe_path.read_bytes()).hexdigest()
    sha_file = DIST_DIR / f"{exe_path.name}.sha256"
    sha_file.write_text(f"{sha256_hex}  {exe_path.name}\n", encoding="utf-8")

    build_tmp = ROOT / "build"
    spec_file = Path.cwd() / "ClawProbe-Desktop-Win64.spec"
    shutil.rmtree(build_tmp, ignore_errors=True)
    if spec_file.exists():
        spec_file.unlink()

    return {
        "exe_path": str(exe_path),
        "sha256": sha256_hex,
        "sha256_file": str(sha_file),
    }


if __name__ == "__main__":
    info = build_win64_executable()
    print(f"Built Windows Desktop Demo: {info['exe_path']} (SHA-256: {info['sha256']})")
