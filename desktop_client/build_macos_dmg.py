#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Builds the standalone macOS `.app` bundle and `.dmg` image (`ClawProbe-Desktop-macOS.dmg`)
using macOS native `hdiutil`, embedding `clawprobe_desktop.py` + `cli_sdk/common_client.py`
and the Unsigned Gatekeeper Bypass README (Opus E-1).
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import shutil
import subprocess
import tempfile
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
CODE_ROOT = THIS_DIR.parent
DIST_DIR = THIS_DIR / "dist"


def build_macos_dmg() -> dict[str, str]:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    dmg_out = DIST_DIR / "ClawProbe-Desktop-macOS.dmg"
    if dmg_out.exists():
        dmg_out.unlink()

    with tempfile.TemporaryDirectory() as tmp:
        stage_dir = Path(tmp) / "ClawProbe_Desktop_Installer"
        app_dir = stage_dir / "ClawProbe Desktop.app" / "Contents"
        macos_dir = app_dir / "MacOS"
        res_dir = app_dir / "Resources"
        sdk_dir = res_dir / "cli_sdk"
        macos_dir.mkdir(parents=True, exist_ok=True)
        sdk_dir.mkdir(parents=True, exist_ok=True)

        # Copy python runtime script & zero-dep SDK (supports both monorepo and open-source clawprobe repo)
        shutil.copy2(THIS_DIR / "clawprobe_desktop.py", res_dir / "clawprobe_desktop.py")
        client_src = CODE_ROOT / "cli_sdk" / "common_client.py"
        if not client_src.exists():
            client_src = CODE_ROOT / "src" / "clawprobe" / "client.py"
        shutil.copy2(client_src, sdk_dir / "common_client.py")
        (sdk_dir / "__init__.py").write_text("", encoding="utf-8")

        # Compile Universal (arm64 + x86_64) Native macOS Cocoa + WKWebView window binary
        from clawprobe_desktop import MACOS_WKWEBVIEW_OBJC_SRC
        objc_src = Path(tmp) / "ClawProbeNativeWindow.m"
        objc_src.write_text(MACOS_WKWEBVIEW_OBJC_SRC, encoding="utf-8")
        native_bin = macos_dir / "ClawProbeNativeWindow"
        subprocess.run(
            [
                "/usr/bin/clang",
                "-O2",
                "-fobjc-arc",
                "-arch",
                "arm64",
                "-arch",
                "x86_64",
                "-framework",
                "Cocoa",
                "-framework",
                "WebKit",
                str(objc_src),
                "-o",
                str(native_bin),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        os.chmod(native_bin, 0o755)

        # Launcher script in Contents/MacOS/ClawProbeDesktop
        launcher = macos_dir / "ClawProbeDesktop"
        launcher.write_text(
            "#!/bin/bash\n"
            'DIR="$(cd "$(dirname "$0")/../Resources" && pwd)"\n'
            'export PYTHONPATH="$DIR"\n'
            'exec /usr/bin/python3 "$DIR/clawprobe_desktop.py" "$@"\n',
            encoding="utf-8",
        )
        os.chmod(launcher, 0o755)

        # Info.plist with clawprobe:// URL scheme handler
        plist_data = {
            "CFBundleName": "ClawProbe Desktop",
            "CFBundleDisplayName": "ClawProbe Desktop (未签名预览版)",
            "CFBundleIdentifier": "com.atooli.clawprobe.desktop",
            "CFBundleVersion": "1.1.0",
            "CFBundleShortVersionString": "1.1.0",
            "CFBundlePackageType": "APPL",
            "CFBundleExecutable": "ClawProbeDesktop",
            "LSMinimumSystemVersion": "12.0",
            "CFBundleURLTypes": [
                {
                    "CFBundleURLName": "ClawProbe Subscription URI",
                    "CFBundleURLSchemes": ["clawprobe"],
                }
            ],
        }
        with (app_dir / "Info.plist").open("wb") as fp:
            plistlib.dump(plist_data, fp)

        # Include honest Gatekeeper bypass instructions inside the DMG
        readme_txt = stage_dir / "首次打开说明_未签名版Gatekeeper放行步骤.txt"
        readme_txt.write_text(
            "【ClawProbe Desktop 桌面工作台 — 首次打开说明（未签名版）】\n\n"
            "1. 推荐零安装方式：直接访问 https://www.atooli.com/#workbench 使用在线网页版工作台（免安装、零拦截）。\n"
            "2. 如使用本桌面客户端（当前处于公测期，未捆绑商业代码签名证书）：\n"
            "   - 方法 A（图形界面）：将「ClawProbe Desktop.app」拖入应用程序后，按住键盘 Control 键并鼠标右键点击图标 -> 选择「打开」-> 在弹出框中点击「仍要打开」。\n"
            "   - 方法 B（终端一行命令移除隔离属性）：\n"
            "     xattr -cr \"/Applications/ClawProbe Desktop.app\"\n",
            encoding="utf-8",
        )

        subprocess.run(
            [
                "/usr/bin/hdiutil",
                "create",
                "-volname",
                "ClawProbe Desktop v1.1",
                "-srcfolder",
                str(stage_dir),
                "-ov",
                "-format",
                "UDZO",
                str(dmg_out),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    sha256_hex = hashlib.sha256(dmg_out.read_bytes()).hexdigest()
    return {
        "dmg_path": str(dmg_out),
        "size_bytes": str(dmg_out.stat().st_size),
        "sha256": sha256_hex,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(build_macos_dmg(), indent=2, ensure_ascii=False))
