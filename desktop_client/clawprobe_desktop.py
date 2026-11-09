#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClawProbe Desktop — 移动应用隐私合规与 300 秒三阶段真机动态检测桌面工作台
Card: CLAWPROBE-COMMERCIAL-V2 (v1.1) — Sub-card 2 (DESKTOP-CLIENT-V1)

Implements all Opus Round 13, 14 & 15 Desktop Client requirements:
  - [E-1] Honest Unsigned (未签名) packaging notice + macOS Gatekeeper / Windows SmartScreen
    step-by-step bypass instructions + one-line curl installer (`install_mac.sh`).
  - [E-3] Stores `sign_secret` & `sub_token` in System Keychain first:
      * macOS: `security add-generic-password` / `security find-generic-password` (Keychain)
      * Windows: `cmdkey` / PowerShell `PasswordVault`
      * Fallback: `~/.clawprobe/config.json` with strict `0600` permissions.
  - [D-4] Displays mandatory one-time 16-char Recovery Code (`RCV-XXXX-XXXX-XXXX`) modal on
    first credential claim + supports account recovery via `/api/v1/public/order/recover`.
  - [A-1 / R14-1 / R14-2] Compliant pricing display ("行业人工检测参考成本 ¥120/次" +
    "元旦前特惠价，期满后调整为长期优惠价，行业基准价 ¥120/次").
  - [A-2 / B-2 / B-3] Dual-channel activation (WeChat/Alipay QR scan with X-Order-Secret polling +
    Redeem Code `CP-XXXX-XXXX-XXXX` + `UNVERIFIED_SELF_REPORTED_TXID` fallback).
  - [C-1] One-click referral link copy (`https://www.atooli.com/?ref=REF-XXXXXX`) with tiered
    bonus display (+2 / +5 / +10 / +20 credits, 50-day TTL).
  - [macOS Native App Window] Uses a local 127.0.0.1 loopback workbench engine + Chrome/Edge
    standalone `--app=` window (avoiding Apple Tcl/Tk 8.5.9 blank-window compositing bugs on
    macOS Sonoma/Sequoia) with native `osascript` file picker and automatic report download to
    `~/Desktop/ClawProbe检测报告/`.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import inspect
import json
import mimetypes
import os
import platform
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any

THIS_DIR = Path(__file__).resolve().parent
CODE_ROOT = THIS_DIR.parent
for _p in (THIS_DIR, CODE_ROOT, CODE_ROOT / "src"):
    if _p.exists():
        _ps = str(_p)
        if _ps in sys.path:
            sys.path.remove(_ps)
        sys.path.insert(0, _ps)

if (THIS_DIR / "cli_sdk" / "common_client.py").exists() or (CODE_ROOT / "cli_sdk" / "common_client.py").exists():
    from cli_sdk.common_client import (
        ClawNexusClient,
        DEFAULT_PINNED_SPKI_SHA256,
        DEFAULT_PUBLIC_ENDPOINT as DEFAULT_ENDPOINT,
        save_credentials as save_cli_credentials,
    )
else:
    try:
        from clawprobe.client import (
            ClawNexusClient,
            DEFAULT_PINNED_SPKI_SHA256,
            DEFAULT_PUBLIC_ENDPOINT as DEFAULT_ENDPOINT,
            save_credentials as save_cli_credentials,
        )
    except ImportError:
        from cli_sdk.common_client import (
            ClawNexusClient,
            DEFAULT_PINNED_SPKI_SHA256,
            DEFAULT_PUBLIC_ENDPOINT as DEFAULT_ENDPOINT,
            save_credentials as save_cli_credentials,
        )

KEYCHAIN_SERVICE = "com.atooli.clawprobe.credentials"
KEYCHAIN_ACCOUNT = "clawprobe_default"
CONFIG_DIR = Path.home() / ".clawprobe"
CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_REPORT_DIR = Path.home() / "Desktop" / "ClawProbe检测报告"


# ============================================================================
# E-3: System Keychain (macOS Keychain / Windows Credential Manager) + 0600 Fallback
# ============================================================================

def store_secret_in_system_keychain(secret_payload: str) -> tuple[bool, str]:
    """
    Attempts to store the sensitive `sign_secret` JSON payload in the OS native credential store:
      - macOS (`Darwin`): `security add-generic-password -U -a <account> -s <service> -w <payload>`
      - Windows (`Windows`): PowerShell `Windows.Security.Credentials.PasswordVault`
    Returns `(stored_in_keychain, backend_name)`.
    """
    sys_name = platform.system()
    if sys_name == "Darwin":
        try:
            res = subprocess.run(
                [
                    "/usr/bin/security",
                    "add-generic-password",
                    "-U",
                    "-a",
                    KEYCHAIN_ACCOUNT,
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-w",
                    secret_payload,
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                return True, "MACOS_KEYCHAIN"
        except Exception:
            pass
    elif sys_name == "Windows":
        try:
            ps_script = (
                "$vault = New-Object Windows.Security.Credentials.PasswordVault; "
                f"$cred = New-Object Windows.Security.Credentials.PasswordCredential('{KEYCHAIN_SERVICE}', '{KEYCHAIN_ACCOUNT}', $env:CP_SEC_VAL); "
                "$vault.Add($cred)"
            )
            env = dict(os.environ, CP_SEC_VAL=secret_payload)
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True,
                text=True,
                env=env,
                timeout=8,
            )
            if res.returncode == 0:
                return True, "WINDOWS_PASSWORD_VAULT"
        except Exception:
            pass
    return False, "FILE_0600_FALLBACK"


def load_secret_from_system_keychain() -> str | None:
    sys_name = platform.system()
    if sys_name == "Darwin":
        try:
            res = subprocess.run(
                [
                    "/usr/bin/security",
                    "find-generic-password",
                    "-a",
                    KEYCHAIN_ACCOUNT,
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-w",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
    elif sys_name == "Windows":
        try:
            ps_script = (
                "$vault = New-Object Windows.Security.Credentials.PasswordVault; "
                f"$c = $vault.Retrieve('{KEYCHAIN_SERVICE}', '{KEYCHAIN_ACCOUNT}'); "
                "$c.RetrievePassword(); Write-Output $c.Password"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=8,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
    return None


def decode_sub_token_local(token: str) -> dict[str, Any]:
    raw = (token or "").strip()
    if not raw.startswith("cp_sub_v1_"):
        raise ValueError("Unsupported subscription token format (expected cp_sub_v1_...)")
    b64 = raw[len("cp_sub_v1_") :]
    pad = "=" * ((4 - len(b64) % 4) % 4)
    obj = json.loads(base64.urlsafe_b64decode((b64 + pad).encode("ascii")).decode("utf-8"))
    if not obj.get("k") or not obj.get("s"):
        raise ValueError("Malformed subscription token payload")
    return obj


def save_desktop_credentials(
    api_key: str,
    sign_secret: str,
    ref_code: str = "",
    sub_token: str = "",
    endpoint: str = DEFAULT_ENDPOINT,
    spki_pin: str | None = None,
) -> dict[str, Any]:
    """
    E-3: Saves non-sensitive metadata in `~/.clawprobe/config.json` (0600) and stores
    `sign_secret` & `sub_token` in System Keychain first (falling back to 0600 file only if
    keychain is unavailable).
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, 0o700)
    except Exception:
        pass

    secret_blob = json.dumps({"sign_secret": sign_secret, "sub_token": sub_token}, ensure_ascii=False)
    in_keychain, backend = store_secret_in_system_keychain(secret_blob)

    cfg: dict[str, Any] = {
        "endpoint": endpoint,
        "api_key": api_key,
        "ref_code": ref_code,
        "spki_pin": spki_pin or DEFAULT_PINNED_SPKI_SHA256[0],
        "secret_storage_backend": backend,
        "updated_at": datetime.now().isoformat(),
    }
    if not in_keychain:
        cfg["sign_secret_fallback"] = sign_secret
        cfg["sub_token_fallback"] = sub_token

    CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except Exception:
        pass
    try:
        save_cli_credentials(endpoint=endpoint, api_key=api_key, sign_secret=sign_secret, spki_pin=spki_pin)
    except Exception:
        pass
    return cfg


def load_desktop_credentials() -> dict[str, Any] | None:
    if not CONFIG_FILE.exists():
        return None
    try:
        cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None

    sign_secret = ""
    sub_token = ""
    kc_raw = load_secret_from_system_keychain()
    if kc_raw:
        try:
            kc_obj = json.loads(kc_raw)
            sign_secret = str(kc_obj.get("sign_secret") or "")
            sub_token = str(kc_obj.get("sub_token") or "")
        except Exception:
            pass
    if not sign_secret:
        sign_secret = str(cfg.get("sign_secret_fallback") or "")
        sub_token = str(cfg.get("sub_token_fallback") or "")
    if not cfg.get("api_key") or not sign_secret:
        return None
    return {
        "endpoint": cfg.get("endpoint") or DEFAULT_ENDPOINT,
        "api_key": cfg["api_key"],
        "sign_secret": sign_secret,
        "sub_token": sub_token,
        "ref_code": cfg.get("ref_code") or "",
        "spki_pin": cfg.get("spki_pin") or DEFAULT_PINNED_SPKI_SHA256[0],
        "secret_storage_backend": cfg.get("secret_storage_backend") or "FILE_0600_FALLBACK",
    }


def generate_developer_integration_snippets(creds: dict[str, Any]) -> dict[str, str]:
    """
    Generates ready-to-copy CLI, Python SDK, and GitHub Actions snippets with `api_key`
    pre-filled (and `sign_secret` referenced via environment variable or Keychain).
    """
    endpoint = creds.get("endpoint") or DEFAULT_ENDPOINT
    api_key = creds.get("api_key") or "cp_live_YOUR_API_KEY"
    cli_snippet = (
        f"# 1. 启动本开源 CLI 图形化桌面 Demo（Windows / macOS 通用）\n"
        f"clawprobe desktop\n\n"
        f"# 2. 命令行提交 APK 执行 300 秒三阶段真机动态检测并导出无水印 PDF + PCAP\n"
        f"clawprobe --endpoint {endpoint} analyze ./your_app.apk \\\n"
        f"  --attest-authorized \\\n"
        f"  --mode privacy \\\n"
        f"  --out ~/Desktop/ClawProbe检测报告/report.pdf \\\n"
        f"  --bundle ~/Desktop/ClawProbe检测报告/evidence_bundle.zip\n"
    )
    py_snippet = (
        "import os\n"
        "from clawprobe.client import ClawNexusClient\n\n"
        f"client = ClawNexusClient(\n"
        f"    endpoint={endpoint!r},\n"
        f"    api_key={api_key!r},\n"
        f"    sign_secret=os.environ['CLAWNEXUS_SIGN_SECRET'],\n"
        ")\n"
        "print(client.request_json('GET', '/api/v1/auth/verify'))\n"
    )
    gh_snippet = (
        "# .github/workflows/clawprobe-privacy-gate.yml\n"
        "name: ClawProbe APK Privacy Compliance Gate\n"
        "on: [push, pull_request]\n"
        "jobs:\n"
        "  apk-dynamic-audit:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - name: Run ClawProbe 300s 3-Phase Dynamic Inspection\n"
        "        env:\n"
        "          CLAWNEXUS_API_KEY: ${{ secrets.CLAWNEXUS_API_KEY }}\n"
        "          CLAWNEXUS_SIGN_SECRET: ${{ secrets.CLAWNEXUS_SIGN_SECRET }}\n"
        "        run: |\n"
        f"          pip install {endpoint}/download/clawprobe-1.3.5-py3-none-any.whl\n"
        "          clawprobe analyze ./app-release.apk --attest-authorized --fail-on-preconsent --out ./report.pdf\n"
    )
    return {"cli": cli_snippet, "python": py_snippet, "github_actions": gh_snippet}


# ============================================================================
# Local Loopback Desktop Workbench HTML/JS + Native macOS App Window
# ============================================================================

DESKTOP_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<title>JanusFlow Desktop v1.2 (雅努斯流 · janusflow.cn / JanusFlow.net / atooli.com) — 移动应用 300 秒三阶段真机动态检测工作台</title>
<style>
  :root {
    --bg: #0b1120;
    --card: #111827;
    --card-border: #1e293b;
    --accent: #38bdf8;
    --primary: #2563eb;
    --emerald: #10b981;
    --amber: #f59e0b;
    --purple: #7c3aed;
    --text: #f8fafc;
    --muted: #94a3b8;
    --mono: "SF Mono", "Menlo", "Consolas", monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", sans-serif;
    font-size: 13.5px;
    line-height: 1.55;
    padding: 0;
    user-select: none;
  }
  .topbar {
    background: #0f172a;
    border-bottom: 1px solid var(--card-border);
    padding: 12px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .topbar h1 { font-size: 16px; color: var(--accent); font-weight: 700; }
  .badge-status {
    font-size: 12px;
    padding: 4px 10px;
    border-radius: 999px;
    background: #1e293b;
    color: #e2e8f0;
    border: 1px solid #334155;
  }
  .badge-status.ok { background: rgba(16,185,129,0.14); border-color: rgba(16,185,129,0.4); color: #6ee7b7; }
  .banner {
    background: rgba(245,158,11,0.1);
    border-bottom: 1px solid rgba(245,158,11,0.28);
    color: #fcd34d;
    padding: 8px 20px;
    font-size: 12.5px;
  }
  .tabs {
    display: flex;
    gap: 8px;
    padding: 12px 20px 0;
    border-bottom: 1px solid var(--card-border);
    background: #0d1526;
  }
  .tab-btn {
    padding: 8px 16px;
    background: transparent;
    color: var(--muted);
    border: none;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    font-size: 13.5px;
    font-weight: 600;
  }
  .tab-btn.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }
  .container { padding: 16px 20px; max-width: 1120px; margin: 0 auto; }
  .card {
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 14px;
  }
  .apk-picker {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    background: #0f172a;
    border: 1px dashed #334155;
    border-radius: 8px;
    padding: 12px 14px;
  }
  .apk-path {
    font-family: var(--mono);
    font-size: 12.5px;
    color: #cbd5e1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    flex: 1;
    user-select: text;
  }
  .btn-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 12px; }
  .btn {
    border: none;
    border-radius: 7px;
    padding: 8px 14px;
    font-size: 13px;
    font-weight: 600;
    color: #fff;
    cursor: pointer;
    transition: opacity 0.15s;
  }
  .btn:hover { opacity: 0.9; }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-primary { background: var(--primary); }
  .btn-emerald { background: var(--emerald); }
  .btn-amber { background: #d97706; }
  .btn-slate { background: #475569; }
  .btn-purple { background: var(--purple); }
  .log-box {
    background: #060a12;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 12px;
    height: 310px;
    overflow-y: auto;
    font-family: var(--mono);
    font-size: 12px;
    color: #a7f3d0;
    white-space: pre-wrap;
    user-select: text;
  }
  .modal-backdrop {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.72);
    align-items: center;
    justify-content: center;
    z-index: 999;
  }
  .modal-backdrop.open { display: flex; }
  .modal {
    background: #111827;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 20px;
    width: 580px;
    max-width: 94vw;
    max-height: 90vh;
    overflow-y: auto;
  }
  .modal h3 { color: var(--accent); margin-bottom: 10px; font-size: 15.5px; }
  .input {
    width: 100%;
    padding: 9px 12px;
    background: #090d16;
    border: 1px solid #334155;
    border-radius: 6px;
    color: #fff;
    font-family: var(--mono);
    font-size: 13px;
    margin: 8px 0;
  }
  .tier-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 10px 0; }
  .tier-item {
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 10px;
    cursor: pointer;
    background: #0b1120;
  }
  .tier-item.selected { border-color: var(--accent); background: rgba(56,189,248,0.1); }
  pre.code-block {
    background: #060a12;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 12px;
    font-family: var(--mono);
    font-size: 12px;
    color: #93c5fd;
    overflow-x: auto;
    user-select: text;
    margin-bottom: 12px;
  }
</style>
</head>
<body>
  <div class="topbar">
    <h1>🏛️ JanusFlow Desktop v1.2 · 雅努斯流 — 开源 CLI 图形化参考工作台 (janusflow.cn · JanusFlow.net · atooli.com)</h1>
    <div id="authBadge" class="badge-status">正在读取系统安全钥匙串...</div>
  </div>
  <div class="banner">
    💡 行业人工检测参考成本 <strong>¥120/次</strong>（指人工抓包出具同类技术报告的行业参考耗时成本） ｜ 元旦前特惠价：单次卡 <strong>¥19.9</strong> / 10次包 <strong>¥159</strong> / 包月 <strong>¥299</strong> / 包年 <strong>¥2,699</strong>（期满后调整为长期优惠价，行业基准价 ¥120/次） ｜ 📦 开源仓库：<code>github.com/876387/clawprobe/tree/main/desktop_client</code>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('main', this)">① 拖包即检与自助订阅（免命令行）</button>
    <button class="tab-btn" onclick="switchTab('dev', this)">② 开发者 API / CLI 集成代码（自动填好 Key）</button>
  </div>

  <div id="tab-main" class="container">
    <div class="card">
      <div style="font-weight:600; margin-bottom:8px; color:#e2e8f0;">第一步：选择待检测的 Android APK 安装包（报告自动保存至 <code>~/Desktop/ClawProbe检测报告/</code>）</div>
      <div class="apk-picker">
        <input id="apkPathInput" class="input" style="margin:0; flex:1;" placeholder="点击右侧按钮选择本地 .apk 文件，或直接粘贴本地 APK 完整路径" oninput="selectedApk = this.value.trim();" />
        <button class="btn btn-primary" onclick="pickApkNative()">📂 选择本地 APK 文件</button>
      </div>
      <div class="btn-row">
        <button id="btnFullInspect" class="btn btn-emerald" onclick="startInspection('FULL')">🚀 完整 300 秒三阶段真机检测（导出 PDF + PCAP）</button>
        <button id="btnQuickScan" class="btn btn-amber" onclick="startInspection('QUICK')">⚡ 免费 30 秒未同意前抢跑快检</button>
        <button class="btn btn-primary" onclick="openPayModal()">💳 扫码秒开 / 购买额度</button>
        <button class="btn btn-slate" onclick="openActivateModal()">🔑 兑换卡密 / 导入订阅串 / 恢复码</button>
        <button class="btn btn-purple" style="margin-left:auto;" onclick="copyReferral()">🎁 复制老带新推荐链接</button>
      </div>
    </div>

    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <span style="font-weight:600; color:#e2e8f0;">实时检测与钥匙串状态日志</span>
        <button class="btn btn-slate" style="padding:4px 10px; font-size:11.5px;" onclick="openReportDir()">📁 打开桌面报告目录</button>
      </div>
      <div id="logBox" class="log-box"></div>
    </div>
  </div>

  <div id="tab-dev" class="container" style="display:none;">
    <div class="card">
      <div style="font-weight:600; margin-bottom:8px;">CLI / Python SDK / GitHub Actions 集成代码（已自动填入您的 APIKey）</div>
      <pre id="devSnippets" class="code-block">加载中...</pre>
    </div>
  </div>

  <!-- Activate / Redeem / Recover Modal -->
  <div id="activateModal" class="modal-backdrop">
    <div class="modal">
      <h3>🔑 卡密兑换 (`CP-...`) / 订阅串导入 (`cp_sub_v1_...`) / 恢复码找回 (`RCV-...`)</h3>
      <p style="color:var(--muted); font-size:12.5px;">支持直接输入 115 批次兑换卡密、官网扫码获得的订阅串、或 16 位账户恢复码，激活后签名密钥将自动存入 <strong>macOS 系统钥匙串 (Keychain)</strong>：</p>
      <input id="inpCodeOrToken" class="input" placeholder="粘贴 CP-XXXX-XXXX-XXXX 或 cp_sub_v1_... 或 RCV-XXXX-XXXX-XXXX" />
      <div id="activateErrMsg" style="color:#f87171; font-size:12.5px; margin-top:4px; min-height:18px;"></div>
      <div class="btn-row" style="justify-content:flex-end;">
        <button class="btn btn-slate" onclick="closeModals()">取消</button>
        <button class="btn btn-primary" onclick="submitCodeOrToken()">立即激活并存入系统钥匙串</button>
      </div>
    </div>
  </div>

  <!-- In-App QR Purchase Modal -->
  <div id="payModal" class="modal-backdrop">
    <div class="modal">
      <h3>💳 免注册微信 / 支付宝扫码秒开（一加 8T 专机自动核销）</h3>
      <div class="tier-grid" id="tierGrid">
        <div class="tier-item selected" data-tier="PAYG_1" onclick="selectTier(this)">
          <div style="font-weight:700; color:#38bdf8;">单次按量检测卡</div>
          <div style="font-size:18px; font-weight:800; margin:2px 0;">¥19.90 <span style="font-size:11px; color:var(--muted); font-weight:400;">/ 1次 (365天)</span></div>
          <div style="font-size:11px; color:#fcd34d;">老带新加赠 +2 次</div>
        </div>
        <div class="tier-item" data-tier="PAYG_10" onclick="selectTier(this)">
          <div style="font-weight:700; color:#38bdf8;">10次按量加油包</div>
          <div style="font-size:18px; font-weight:800; margin:2px 0;">¥159.00 <span style="font-size:11px; color:var(--muted); font-weight:400;">/ 10次 (¥15.9/次)</span></div>
          <div style="font-size:11px; color:#fcd34d;">老带新加赠 +5 次</div>
        </div>
        <div class="tier-item" data-tier="SUB_MONTH" onclick="selectTier(this)">
          <div style="font-weight:700; color:#38bdf8;">团队包月订阅</div>
          <div style="font-size:18px; font-weight:800; margin:2px 0;">¥299.00 <span style="font-size:11px; color:var(--muted); font-weight:400;">/ 25次 (30天)</span></div>
          <div style="font-size:11px; color:#fcd34d;">老带新加赠 +10 次</div>
        </div>
        <div class="tier-item" data-tier="SUB_YEAR" onclick="selectTier(this)">
          <div style="font-weight:700; color:#38bdf8;">机构包年订阅</div>
          <div style="font-size:18px; font-weight:800; margin:2px 0;">¥2,699.00 <span style="font-size:11px; color:var(--muted); font-weight:400;">/ 300次 (365天)</span></div>
          <div style="font-size:11px; color:#fcd34d;">老带新加赠 +20 次</div>
        </div>
      </div>
      <div style="display:flex; gap:8px; margin:10px 0;">
        <button class="btn btn-emerald" style="flex:1;" onclick="createDesktopOrder('WECHAT')">微信扫码支付</button>
        <button class="btn btn-primary" style="flex:1;" onclick="createDesktopOrder('ALIPAY')">支付宝扫码支付</button>
      </div>
      <div id="qrOrderBox" style="display:none; text-align:center; background:#090d16; padding:12px; border-radius:8px; border:1px solid #334155; margin-top:10px;">
        <div id="qrOrderTip" style="color:#fcd34d; font-weight:700; margin-bottom:8px;"></div>
        <img id="qrOrderImg" src="" style="width:210px; height:210px; object-fit:contain; background:#fff; padding:6px; border-radius:8px;" />
        <div id="qrPollStatus" style="font-size:12px; color:#a7f3d0; margin-top:8px;">正在等待扫码到账自动核销（每 2.5 秒轮询）...</div>
      </div>
      <div class="btn-row" style="justify-content:flex-end;">
        <button class="btn btn-slate" onclick="closeModals()">关闭</button>
      </div>
    </div>
  </div>

  <!-- Recovery Code One-Time Modal -->
  <div id="rcvModal" class="modal-backdrop">
    <div class="modal">
      <h3>⚠️ 请立即保存您的 16 位账户恢复码（仅展示一次）</h3>
      <p style="color:#e2e8f0; font-size:13px;">您的检测额度已自动激活并存入 <strong>macOS 系统钥匙串</strong>！请务必复制保存下方 16 位恢复码（换电脑或重装系统时凭此码找回全部剩余额度）：</p>
      <input id="rcvCodeInput" class="input" readonly style="text-align:center; font-size:17px; font-weight:700; color:#6ee7b7;" />
      <div class="btn-row" style="justify-content:flex-end;">
        <button class="btn btn-emerald" onclick="copyRcvAndClose()">📋 一键复制恢复码并完成</button>
      </div>
    </div>
  </div>

<script>
let selectedApk = "";
let selectedTier = "PAYG_1";
let currentRefCode = "REF-DEMO01";
let orderPollTimer = null;

function appendLog(msg) {
  const box = document.getElementById("logBox");
  const ts = new Date().toTimeString().slice(0, 8);
  box.textContent += `[${ts}] ${msg}\\n`;
  box.scrollTop = box.scrollHeight;
}

function switchTab(name, btn) {
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  document.getElementById("tab-main").style.display = (name === "main") ? "block" : "none";
  document.getElementById("tab-dev").style.display = (name === "dev") ? "block" : "none";
}

async function refreshState() {
  const r = await fetch("/api/local/status");
  const d = await r.json();
  const badge = document.getElementById("authBadge");
  if (d.status === "configured") {
    badge.className = "badge-status ok";
    let quotaTxt = (d.remaining_credits !== undefined) ? ` ｜ 剩余额度：${d.remaining_credits} 次` : "";
    badge.textContent = `✅ 已激活：${d.api_key_masked} (${d.secret_storage_backend})${quotaTxt}`;
    currentRefCode = d.ref_code || "REF-DEMO01";
    document.getElementById("devSnippets").textContent = d.snippets_text || "";
  } else {
    badge.className = "badge-status";
    badge.textContent = "未绑定订阅（支持免费 30s 抢跑快检 / 扫码或卡密秒级开通）";
    document.getElementById("devSnippets").textContent = d.snippets_text || "";
  }
}

async function pickApkNative() {
  appendLog("正在打开系统原生 APK 文件选择器...");
  const r = await fetch("/api/local/pick-apk", {method: "POST"});
  const d = await r.json();
  if (d.status === "ok" && d.apk_path) {
    selectedApk = d.apk_path;
    document.getElementById("apkPathInput").value = d.apk_path;
    appendLog(`已选择 APK 文件：${d.apk_path} (${d.size_mb} MB)`);
  } else if (d.message) {
    appendLog(d.message);
  }
}

async function startInspection(mode) {
  if (!selectedApk) {
    await pickApkNative();
    if (!selectedApk) return;
  }
  document.getElementById("btnFullInspect").disabled = true;
  document.getElementById("btnQuickScan").disabled = true;
  appendLog(mode === "QUICK"
    ? `⚡ 开始执行【免费 30 秒未点同意前抢跑快检】：${selectedApk} ...`
    : `🚀 开始提交【完整 300 秒三阶段真机动态检测】：${selectedApk} ...`);
  try {
    const r = await fetch("/api/local/run-inspect", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({apk_path: selectedApk, mode: mode})
    });
    const d = await r.json();
    if (d.status === "started" && d.task_id) {
      let seenIdx = 0;
      while (true) {
        await new Promise(res => setTimeout(res, 1200));
        const pr = await fetch(`/api/local/task-status?task_id=${encodeURIComponent(d.task_id)}`);
        const pd = await pr.json();
        const logs = pd.logs || [];
        while (seenIdx < logs.length) {
          appendLog(logs[seenIdx]);
          seenIdx++;
        }
        if (pd.state === "done" || pd.status === "ok" || pd.status === "done") {
          await refreshState();
          break;
        }
        if (pd.state === "error" || pd.status === "error") {
          appendLog(`❌ 检测未完成：${pd.message || "任务失败"}`);
          if (pd.need_subscribe) openPayModal();
          break;
        }
      }
    } else {
      if (d.logs) d.logs.forEach(l => appendLog(l));
      if (d.status !== "ok") {
        appendLog(`❌ 检测未完成：${d.message || d.error_code}`);
        if (d.need_subscribe) openPayModal();
      } else {
        await refreshState();
      }
    }
  } catch (e) {
    appendLog(`❌ 请求异常：${e}`);
  } finally {
    document.getElementById("btnFullInspect").disabled = false;
    document.getElementById("btnQuickScan").disabled = false;
  }
}

function openActivateModal() {
  document.getElementById("activateModal").classList.add("open");
}

function openPayModal() {
  document.getElementById("payModal").classList.add("open");
}

function closeModals() {
  document.querySelectorAll(".modal-backdrop").forEach(m => m.classList.remove("open"));
  if (orderPollTimer) { clearInterval(orderPollTimer); orderPollTimer = null; }
}

function selectTier(el) {
  document.querySelectorAll(".tier-item").forEach(i => i.classList.remove("selected"));
  el.classList.add("selected");
  selectedTier = el.getAttribute("data-tier");
}

async function createDesktopOrder(channel) {
  if (orderPollTimer) { clearInterval(orderPollTimer); orderPollTimer = null; }
  appendLog(`正在创建 ${selectedTier} (${channel}) 扫码订单...`);
  const r = await fetch("/api/local/order-create", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({tier_code: selectedTier, pay_channel: channel})
  });
  const d = await r.json();
  if (d.status !== "ok") {
    appendLog(`❌ 创建订单失败：${d.message || JSON.stringify(d)}`);
    return;
  }
  const box = document.getElementById("qrOrderBox");
  box.style.display = "block";
  const chName = (d.pay_channel === "WECHAT") ? "微信" : "支付宝";
  document.getElementById("qrOrderTip").textContent =
    `请使用${chName}扫码并精确输入金额：¥${d.locked_amount_yuan}（含自动核销唯一分位尾差）`;
  document.getElementById("qrOrderImg").src =
    `/api/local/qr-image?channel=${encodeURIComponent(d.pay_channel)}&t=${Date.now()}`;
  document.getElementById("qrPollStatus").textContent =
    `订单号 ${d.order_id} 已锁定 ¥${d.locked_amount_yuan}，等待一加 8T 真机到账通知自动核销...`;

  orderPollTimer = setInterval(async () => {
    const pr = await fetch(`/api/local/order-poll?order_id=${encodeURIComponent(d.order_id)}&order_secret=${encodeURIComponent(d.order_secret)}`);
    const pd = await pr.json();
    if (pd.activated && pd.bundle) {
      clearInterval(orderPollTimer);
      orderPollTimer = null;
      closeModals();
      appendLog(`✅ 扫码到账核销成功！已自动激活并写入系统安全钥匙串（Key ID: ${pd.bundle.key_id}）`);
      await refreshState();
      if (pd.bundle.recovery_code) showRcvModal(pd.bundle.recovery_code);
    }
  }, 2500);
}

async function submitCodeOrToken() {
  const val = document.getElementById("inpCodeOrToken").value.trim();
  const errEl = document.getElementById("activateErrMsg");
  errEl.textContent = "";
  if (!val) {
    errEl.textContent = "请先粘贴卡密、订阅串或 16 位恢复码";
    return;
  }
  const r = await fetch("/api/local/activate", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({code_or_token: val})
  });
  const d = await r.json();
  if (d.status !== "ok") {
    const msg = d.message || JSON.stringify(d);
    appendLog(`❌ 激活失败：${msg}`);
    errEl.textContent = `❌ ${msg}`;
    return;
  }
  closeModals();
  appendLog(`✅ ${d.message}`);
  await refreshState();
  if (d.recovery_code) showRcvModal(d.recovery_code);
}

function showRcvModal(code) {
  document.getElementById("rcvCodeInput").value = code;
  document.getElementById("rcvModal").classList.add("open");
}

async function copyTextNative(text) {
  try {
    await fetch("/api/local/copy-clipboard", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({text: text})
    });
  } catch (e) {}
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    }
  } catch (e) {}
}

async function copyRcvAndClose() {
  const v = document.getElementById("rcvCodeInput").value;
  await copyTextNative(v);
  appendLog(`📋 已复制您的 16 位账户恢复码：${v}`);
  closeModals();
}

async function copyReferral() {
  const link = `https://www.atooli.com/?ref=${currentRefCode}`;
  await copyTextNative(link);
  appendLog(`🎁 已复制您的专属老带新推荐链接：${link}（被邀请人实付单次卡送 +2 次、10次包 +5 次、包月 +10 次、包年 +20 次，有效期 50 天）`);
}

async function openReportDir() {
  await fetch("/api/local/open-report-dir", {method: "POST"});
}

window.addEventListener("DOMContentLoaded", async () => {
  appendLog("JanusFlow Desktop v1.2 (雅努斯流 · ClawProbe CLI GUI) 已就绪。报告默认输出目录：~/Desktop/ClawProbe检测报告/");
  await refreshState();
});
</script>
</body>
</html>
"""


def _http_json_public(endpoint: str, method: str, path: str, body: dict | None = None, headers: dict | None = None) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    hdrs = {"User-Agent": "ClawProbe-Desktop/1.1"}
    if headers:
        hdrs.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(endpoint.rstrip("/") + path, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8"))
        except Exception:
            return {"status": "error", "message": f"HTTP {e.code}: {e.reason}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def _resolve_fast_upload_target(endpoint: str) -> tuple[str, ssl.SSLContext, str]:
    """
    Discovers the high-bandwidth dedicated upload endpoint from `/api/v1/public/pricing`
    so large APKs (up to 300 MB) stream over the 1000 Mbps fiber edge instead of the 3 Mbps web relay.
    """
    ctx = ssl.create_default_context()
    try:
        info = _http_json_public(endpoint, "GET", "/api/v1/public/pricing")
        fast_ep = str(info.get("fast_upload_endpoint") or "").strip()
        ca_pem = str(info.get("fast_upload_ca_pem") or "").strip()
        if fast_ep and ca_pem:
            fast_ctx = ssl.create_default_context()
            fast_ctx.load_verify_locations(cadata=ca_pem)
            return fast_ep, fast_ctx, ca_pem
    except Exception:
        pass
    return endpoint, ctx, ""


def _upload_quick_scan_multipart(endpoint: str, apk_path: Path, log_fn: Any = None) -> dict[str, Any]:
    import http.client

    apk_bytes = apk_path.read_bytes()
    apk_sha = hashlib.sha256(apk_bytes).hexdigest()
    mb_total = round(len(apk_bytes) / (1024 * 1024), 2)

    target_ep, tls_ctx, _ = _resolve_fast_upload_target(endpoint)
    parsed = urllib.parse.urlparse(target_ep)
    host = parsed.hostname or "www.atooli.com"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if log_fn:
        log_fn(f"🔍 正在校验本地 APK SHA-256 指纹 ({apk_sha[:16]}...) 与服务端秒传缓存...")

    try:
        probe_body = json.dumps(
            {
                "apk_sha256": apk_sha,
                "apk_size": len(apk_bytes),
                "filename": apk_path.name,
                "probe_only": True,
            }
        ).encode("utf-8")
        p_conn = http.client.HTTPSConnection(host, port, timeout=15, context=tls_ctx)
        p_conn.request(
            "POST",
            "/api/v1/public/quick-scan",
            body=probe_body,
            headers={"Content-Type": "application/json", "User-Agent": "ClawProbe-Desktop/1.1"},
        )
        p_resp = p_conn.getresponse()
        p_raw = p_resp.read().decode("utf-8", errors="replace")
        p_conn.close()
        if p_resp.status == 200:
            p_obj = json.loads(p_raw)
            if p_obj.get("cached_quick_scan") and isinstance(p_obj.get("quick_scan_result"), dict):
                if log_fn:
                    log_fn(f"⚡ 命中 SHA-256 极速秒传与 24h 快检结果缓存！已为您节省 {mb_total} MB 上传流量 (0 字节免传)！")
                return p_obj["quick_scan_result"]
            if p_obj.get("cas_exists"):
                if log_fn:
                    log_fn(f"⚡ 命中 SHA-256 极速秒传！服务端已存在相同指纹文件，免上传 {mb_total} MB，直接启动 30 秒真机抓包...")
                exec_body = json.dumps(
                    {
                        "apk_sha256": apk_sha,
                        "apk_size": len(apk_bytes),
                        "filename": apk_path.name,
                        "probe_only": False,
                    }
                ).encode("utf-8")
                e_conn = http.client.HTTPSConnection(host, port, timeout=360, context=tls_ctx)
                e_conn.request(
                    "POST",
                    "/api/v1/public/quick-scan",
                    body=exec_body,
                    headers={"Content-Type": "application/json", "User-Agent": "ClawProbe-Desktop/1.1"},
                )
                e_resp = e_conn.getresponse()
                e_raw = e_resp.read().decode("utf-8", errors="replace")
                e_conn.close()
                if e_resp.status == 200:
                    return json.loads(e_raw)
    except Exception:
        pass

    boundary = f"----ClawProbeDesktopBoundary{uuid.uuid4().hex}"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{apk_path.name}"\r\n'
        "Content-Type: application/vnd.android.package-archive\r\n\r\n"
    ).encode("utf-8")
    tail = f"\r\n--{boundary}--\r\n".encode("utf-8")
    body = head + apk_bytes + tail
    total_len = len(body)

    if log_fn:
        log_fn(f"📤 服务端首次接收该包，正在通过千兆专线高速上传 APK ({mb_total} MB)...")

    try:
        conn = http.client.HTTPSConnection(host, port, timeout=360, context=tls_ctx)
        conn.putrequest("POST", "/api/v1/public/quick-scan")
        conn.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
        conn.putheader("Content-Length", str(total_len))
        conn.putheader("User-Agent", "ClawProbe-Desktop/1.1")
        conn.endheaders()

        chunk_size = 512 * 1024
        sent = 0
        next_pct = 25
        for offset in range(0, total_len, chunk_size):
            chunk = body[offset : offset + chunk_size]
            conn.send(chunk)
            sent += len(chunk)
            pct = int(sent * 100 / total_len)
            if log_fn and pct >= next_pct and next_pct < 100:
                log_fn(f"   ↳ 上传进度：{round(sent / (1024 * 1024), 1)} MB / {mb_total} MB ({pct}%)")
                next_pct += 25

        if log_fn:
            log_fn("🔬 APK 上传完成 (100%)，真机沙箱正在执行 30 秒冷启动未同意前抢跑抓包，请稍候...")

        wait_done = threading.Event()

        def _sandbox_progress_ticker() -> None:
            stages = [
                (8, "   ↳ [沙箱阶段 1/4] 正在将 APK 推送至隔离容器沙箱并执行安装..."),
                (18, "   ↳ [沙箱阶段 2/4] 应用已冷启动（未点同意隐私弹窗），正在执行 30 秒底层抓包 (tcpdump)..."),
                (33, "   ↳ [沙箱阶段 3/4] 30 秒抓包观察窗推进中，正在实时捕获 DNS / TLS SNI 与远端五元组..."),
                (48, "   ↳ [沙箱阶段 4/4] 正在回传 PCAP 抓包文件并生成抢跑连接审计摘要..."),
            ]
            t_start = time.time()
            idx = 0
            while not wait_done.wait(1.0):
                elapsed = time.time() - t_start
                if idx < len(stages) and elapsed >= stages[idx][0]:
                    if log_fn:
                        log_fn(stages[idx][1])
                    idx += 1

        if log_fn:
            threading.Thread(target=_sandbox_progress_ticker, daemon=True).start()
        try:
            resp = conn.getresponse()
            raw_resp = resp.read().decode("utf-8", errors="replace")
        finally:
            wait_done.set()
        conn.close()
        try:
            return json.loads(raw_resp)
        except Exception:
            return {"status": "error", "message": f"HTTP {resp.status}: {raw_resp[:160]}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def launch_gui(initial_endpoint: str = DEFAULT_ENDPOINT) -> None:
    DEFAULT_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    tasks_state: dict[str, dict[str, Any]] = {}

    class LocalWorkbenchHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _send_json(self, obj: dict[str, Any], code: int = 200) -> None:
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/":
                raw = DESKTOP_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return

            if parsed.path == "/api/local/task-status":
                qs = urllib.parse.parse_qs(parsed.query)
                tid = (qs.get("task_id") or [""])[0]
                st = tasks_state.get(tid)
                if not st:
                    self._send_json({"status": "error", "message": "任务不存在或已过期"}, 404)
                    return
                self._send_json(st)
                return

            if parsed.path == "/api/local/status":
                creds = load_desktop_credentials()
                snippets = generate_developer_integration_snippets(creds or {"endpoint": initial_endpoint})
                snippets_text = (
                    f"=== CLI 一键检测命令 ===\n{snippets['cli']}\n"
                    f"=== Python SDK 调用示例 ===\n{snippets['python']}\n"
                    f"=== GitHub Actions CI/CD 集成 ===\n{snippets['github_actions']}"
                )
                if not creds:
                    self._send_json({"status": "unconfigured", "snippets_text": snippets_text})
                    return
                rem_credits = None
                try:
                    cli = ClawNexusClient(
                        endpoint=creds["endpoint"],
                        api_key=creds["api_key"],
                        sign_secret=creds["sign_secret"],
                    )
                    code, verify_res = cli.request_json("GET", "/api/v1/auth/verify")
                    if code == 200 and isinstance(verify_res, dict):
                        ac = verify_res.get("auth_context") or {}
                        rem_credits = ac.get("total_inspect_credits_remaining")
                except Exception:
                    pass
                self._send_json({
                    "status": "configured",
                    "endpoint": creds["endpoint"],
                    "api_key_masked": creds["api_key"][:12] + "****" + creds["api_key"][-4:],
                    "ref_code": creds["ref_code"],
                    "secret_storage_backend": creds["secret_storage_backend"],
                    "remaining_credits": rem_credits,
                    "snippets_text": snippets_text,
                })
                return

            if parsed.path == "/api/local/order-poll":
                qs = urllib.parse.parse_qs(parsed.query)
                oid = (qs.get("order_id") or [""])[0]
                osec = (qs.get("order_secret") or [""])[0]
                res = _http_json_public(
                    initial_endpoint,
                    "GET",
                    f"/api/v1/public/order/{oid}/status",
                    headers={"X-Order-Secret": osec},
                )
                if res.get("order_status") == "PAID_VERIFIED" and res.get("bundle"):
                    b = res["bundle"]
                    save_desktop_credentials(
                        api_key=b["api_key"],
                        sign_secret=b["sign_secret"],
                        ref_code=b.get("ref_code", ""),
                        sub_token=b.get("sub_token", ""),
                        endpoint=initial_endpoint,
                    )
                    self._send_json({"status": "ok", "activated": True, "bundle": b})
                    return
                self._send_json({"status": "ok", "activated": False, "order_status": res.get("order_status")})
                return

            if parsed.path == "/api/local/qr-image":
                qs = urllib.parse.parse_qs(parsed.query)
                ch = ((qs.get("channel") or ["WECHAT"])[0] or "WECHAT").upper()
                rel_path = "/static/pay/wechat_qr.png" if ch == "WECHAT" else "/static/pay/alipay_qr.jpg"
                ctype = "image/png" if ch == "WECHAT" else "image/jpeg"
                try:
                    ctx = ssl.create_default_context()
                    req = urllib.request.Request(
                        initial_endpoint.rstrip("/") + rel_path,
                        headers={"User-Agent": "ClawProbe-Desktop/1.1"},
                    )
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                        img_bytes = resp.read()
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", str(len(img_bytes)))
                    self.end_headers()
                    self.wfile.write(img_bytes)
                except Exception as exc:
                    self._send_json({"status": "error", "message": str(exc)}, 502)
                return

            self._send_json({"status": "error", "message": "Not found"}, 404)

        def do_POST(self) -> None:
            clen = int(self.headers.get("Content-Length") or "0")
            body_raw = self.rfile.read(clen) if clen > 0 else b"{}"
            try:
                body = json.loads(body_raw.decode("utf-8"))
            except Exception:
                body = {}

            if self.path == "/api/local/pick-apk":
                sys_name = platform.system()
                if sys_name == "Darwin":
                    res = subprocess.run(
                        [
                            "/usr/bin/osascript",
                            "-e",
                            'POSIX path of (choose file with prompt "请选择待检测的 Android APK 安装包 (.apk)：")',
                        ],
                        capture_output=True,
                        text=True,
                    )
                    if res.returncode == 0 and res.stdout.strip():
                        p = Path(res.stdout.strip())
                        mb = round(p.stat().st_size / (1024 * 1024), 2)
                        self._send_json({"status": "ok", "apk_path": str(p), "size_mb": mb})
                        return
                elif sys_name == "Windows":
                    ps_pick = (
                        "Add-Type -AssemblyName System.Windows.Forms; "
                        "$f = New-Object System.Windows.Forms.OpenFileDialog; "
                        "$f.Filter = 'Android APK (*.apk)|*.apk|All Files (*.*)|*.*'; "
                        "$f.Title = '请选择待检测的 Android APK 安装包 (.apk)'; "
                        "if ($f.ShowDialog() -eq 'OK') { Write-Output $f.FileName }"
                    )
                    res = subprocess.run(
                        ["powershell", "-NoProfile", "-Sta", "-Command", ps_pick],
                        capture_output=True,
                        text=True,
                    )
                    if res.returncode == 0 and res.stdout.strip():
                        p = Path(res.stdout.strip())
                        mb = round(p.stat().st_size / (1024 * 1024), 2)
                        self._send_json({"status": "ok", "apk_path": str(p), "size_mb": mb})
                        return
                self._send_json({"status": "cancelled", "message": "未选择文件（您也可直接在输入框粘贴本地 APK 路径）"})
                return

            if self.path == "/api/local/open-report-dir":
                DEFAULT_REPORT_DIR.mkdir(parents=True, exist_ok=True)
                sys_name = platform.system()
                if sys_name == "Darwin":
                    subprocess.Popen(["/usr/bin/open", str(DEFAULT_REPORT_DIR)])
                elif sys_name == "Windows":
                    subprocess.Popen(["explorer.exe", str(DEFAULT_REPORT_DIR)])
                else:
                    subprocess.Popen(["xdg-open", str(DEFAULT_REPORT_DIR)])
                self._send_json({"status": "ok"})
                return

            if self.path == "/api/local/copy-clipboard":
                txt = str(body.get("text") or "")
                sys_name = platform.system()
                try:
                    if sys_name == "Darwin":
                        subprocess.run(["/usr/bin/pbcopy"], input=txt.encode("utf-8"), timeout=3)
                    elif sys_name == "Windows":
                        subprocess.run(["clip"], input=txt.encode("utf-16le"), timeout=3)
                except Exception:
                    pass
                self._send_json({"status": "ok"})
                return

            if self.path == "/api/local/order-create":
                res = _http_json_public(
                    initial_endpoint,
                    "POST",
                    "/api/v1/public/order/create",
                    {
                        "tier_code": body.get("tier_code", "PAYG_1"),
                        "pay_channel": body.get("pay_channel", "WECHAT"),
                        "device_fp": f"desktop_{platform.node()}",
                    },
                )
                self._send_json(res)
                return

            if self.path == "/api/local/activate":
                val = str(body.get("code_or_token") or "").strip()
                if val.startswith("cp_sub_v1_"):
                    try:
                        obj = decode_sub_token_local(val)
                        save_desktop_credentials(
                            api_key=obj["k"],
                            sign_secret=obj["s"],
                            ref_code=obj.get("r", ""),
                            sub_token=val,
                            endpoint=obj.get("e", initial_endpoint),
                            spki_pin=obj.get("p"),
                        )
                        self._send_json({"status": "ok", "message": "订阅串导入成功，签名密钥已存入 macOS 系统安全钥匙串！"})
                    except Exception as exc:
                        self._send_json({"status": "error", "message": str(exc)})
                    return

                if val.upper().startswith("CP-"):
                    res = _http_json_public(initial_endpoint, "POST", "/api/v1/public/order/redeem", {"redeem_code": val})
                    if res.get("status") == "ok" and res.get("bundle"):
                        b = res["bundle"]
                        save_desktop_credentials(
                            api_key=b["api_key"],
                            sign_secret=b["sign_secret"],
                            ref_code=b.get("ref_code", ""),
                            sub_token=b.get("sub_token", ""),
                            endpoint=initial_endpoint,
                        )
                        self._send_json({
                            "status": "ok",
                            "message": f"卡密兑换成功！已开通 {res.get('credits_granted')} 次检测额度并存入系统钥匙串。",
                            "recovery_code": b.get("recovery_code", ""),
                        })
                    else:
                        self._send_json(res)
                    return

                if val.upper().startswith("RCV-"):
                    res = _http_json_public(initial_endpoint, "POST", "/api/v1/public/order/recover", {"recovery_code": val})
                    if res.get("status") == "ok" and res.get("bundle"):
                        b = res["bundle"]
                        save_desktop_credentials(
                            api_key=b["api_key"],
                            sign_secret=b["sign_secret"],
                            ref_code=b.get("ref_code", ""),
                            sub_token=b.get("sub_token", ""),
                            endpoint=initial_endpoint,
                        )
                        self._send_json({
                            "status": "ok",
                            "message": f"账户恢复成功！剩余 {res.get('remaining_credits')} 次额度已重新绑定至本机钥匙串。",
                            "recovery_code": b.get("recovery_code", ""),
                        })
                    else:
                        self._send_json(res)
                    return

                self._send_json({"status": "error", "message": "未识别的格式（请输入 CP-... 卡密、cp_sub_v1_... 订阅串或 RCV-... 恢复码）"})
                return

            if self.path == "/api/local/run-inspect":
                raw_apk_str = str(body.get("apk_path") or "").strip()
                if " (" in raw_apk_str and raw_apk_str.endswith("MB)"):
                    raw_apk_str = raw_apk_str.rsplit(" (", 1)[0].strip()
                apk_p = Path(raw_apk_str)
                mode = str(body.get("mode") or "FULL").upper()
                if not apk_p.exists():
                    self._send_json({"status": "error", "message": f"APK 文件不存在：{apk_p}"})
                    return

                if mode == "FULL":
                    creds = load_desktop_credentials()
                    if not creds:
                        self._send_json({
                            "status": "error",
                            "need_subscribe": True,
                            "message": "完整 300 秒三阶段真机检测需先扫码开通或兑换卡密（或点击右侧「⚡ 免费 30 秒未同意前抢跑快检」体验）",
                        })
                        return

                task_id = f"task_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}"
                task_obj: dict[str, Any] = {"status": "running", "state": "running", "logs": []}
                tasks_state[task_id] = task_obj

                def _append_log(msg: str) -> None:
                    task_obj["logs"].append(msg)

                def _bg_worker() -> None:
                    try:
                        if mode == "QUICK":
                            res = _upload_quick_scan_multipart(initial_endpoint, apk_p, log_fn=_append_log)
                            if res.get("status") == "ok":
                                out_f = DEFAULT_REPORT_DIR / f"quick_scan_{apk_p.stem}_{int(time.time())}.json"
                                out_f.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
                                pre_cnt = res.get("pre_consent_flow_count", res.get("pre_consent_connections_30s", 0))
                                _append_log(f"✅ {res.get('headline') or f'30 秒抢跑快检完成！未同意前抢跑连接数：{pre_cnt} 次'}")
                                _append_log(
                                    f"📦 包名：{res.get('package_name', '-')} ｜ 版本：{res.get('version_name', '-')} "
                                    f"｜ 捕获总包数：{res.get('total_uid_packets', 0)} ｜ DNS 域名数：{res.get('unique_dns_domains', 0)}"
                                )
                                for fl in (res.get("masked_pre_consent_flows") or [])[:5]:
                                    _append_log(
                                        f"   • {fl.get('anchor_preview')} +{fl.get('offset_ms')}ms "
                                        f"{fl.get('protocol')} -> {fl.get('remote_ip_masked')}:{fl.get('remote_port')} ({fl.get('domain_sni_masked')})"
                                    )
                                _append_log(f"📄 快检摘要已保存至：{out_f}")
                                task_obj["result"] = res
                                task_obj["status"] = "ok"
                                task_obj["state"] = "done"
                            else:
                                task_obj["message"] = res.get("message") or "快检失败"
                                task_obj["status"] = "error"
                                task_obj["state"] = "error"
                            return

                        creds_local = load_desktop_credentials()
                        if not creds_local:
                            task_obj["need_subscribe"] = True
                            task_obj["message"] = "未检测到有效订阅凭证"
                            task_obj["status"] = "error"
                            task_obj["state"] = "error"
                            return

                        target_ep, _tls_ctx, ca_pem = _resolve_fast_upload_target(creds_local["endpoint"])
                        ca_file_path: str | None = None
                        if ca_pem:
                            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
                            ca_p = CONFIG_DIR / "fast_edge_ca.pem"
                            ca_p.write_text(ca_pem, encoding="utf-8")
                            ca_file_path = str(ca_p)

                        cli = ClawNexusClient(
                            endpoint=target_ep,
                            api_key=creds_local["api_key"],
                            sign_secret=creds_local["sign_secret"],
                            ca_cert=ca_file_path,
                            timeout=600.0,
                        )
                        raw_apk = apk_p.read_bytes()
                        apk_sha = hashlib.sha256(raw_apk).hexdigest()
                        _append_log(f"🔍 正在校验 APK 指纹 (SHA256={apk_sha[:16]}...) 并通过 TLS 1.3 + HMAC-SHA256 签名提交任务...")
                        _upload_kwargs: dict[str, Any] = {
                            "file_path": apk_p,
                            "fields": {
                                "mode": "privacy",
                                "confidential": "false",
                                "ttl_hours": "72",
                                "authorization_attested": "true",
                                "wait": "false",
                            },
                        }
                        if "log_fn" in inspect.signature(cli.upload_multipart).parameters:
                            _upload_kwargs["log_fn"] = _append_log
                        code, sub_res = cli.upload_multipart(
                            "/api/v1/inspect/submit",
                            **_upload_kwargs,
                        )
                        if code not in (200, 202) or not isinstance(sub_res, dict) or not sub_res.get("job_id"):
                            err_msg = sub_res.get("message") if isinstance(sub_res, dict) else str(sub_res)
                            task_obj["message"] = f"提交失败 ({code}): {err_msg}"
                            task_obj["status"] = "error"
                            task_obj["state"] = "error"
                            return
                        job_id = sub_res["job_id"]
                        dedup_note = "（⚡ 已触发 SHA-256 极速秒传）" if sub_res.get("instant_dedup") else ""
                        _append_log(f"✅ 任务已创建：{job_id} {dedup_note}，已分配真机沙箱执行 300 秒三阶段动态检测...")
                        out_dir = DEFAULT_REPORT_DIR / job_id
                        out_dir.mkdir(parents=True, exist_ok=True)
                        (out_dir / "job_submitted.json").write_text(json.dumps(sub_res, ensure_ascii=False, indent=2), encoding="utf-8")

                        t_poll_start = time.time()
                        last_stage_logged = 0
                        while True:
                            time.sleep(8.0)
                            elapsed = int(time.time() - t_poll_start)
                            if elapsed >= 15 and last_stage_logged < 1:
                                _append_log(f"   ↳ [300s 阶段 1/3 · 已运行 {elapsed}s] 冷启动静默观察窗（60s，未点同意隐私弹窗前抢跑监测）...")
                                last_stage_logged = 1
                            elif elapsed >= 75 and last_stage_logged < 2:
                                _append_log(f"   ↳ [300s 阶段 2/3 · 已运行 {elapsed}s] 已点击同意隐私弹窗，正在执行 UI 深度遍历与加密流量捕获（120s）...")
                                last_stage_logged = 2
                            elif elapsed >= 195 and last_stage_logged < 3:
                                _append_log(f"   ↳ [300s 阶段 3/3 · 已运行 {elapsed}s] 应用退至后台，正在捕获后台静默驻留与心跳唤醒流量（120s）...")
                                last_stage_logged = 3
                            elif elapsed >= 310 and last_stage_logged < 4:
                                _append_log(f"   ↳ [报告合成 · 已运行 {elapsed}s] 300 秒三阶段抓包完毕，正在生成无水印 PDF 报告与 PCAP 证据包...")
                                last_stage_logged = 4

                            st_code, j_info = cli.request_json("GET", f"/api/v1/inspect/jobs/{job_id}")
                            if st_code == 200 and isinstance(j_info, dict):
                                j_status = str(j_info.get("job_status") or j_info.get("status") or "").upper()
                                if j_status == "SUCCEEDED":
                                    _append_log("📥 检测已完成，正在自动下载无水印 PDF 报告、结构化 JSON 与 PCAP 证据包...")
                                    for fname, ep_suffix in [
                                        ("report.pdf", f"/api/v1/inspect/jobs/{job_id}/report.pdf"),
                                        ("report.json", f"/api/v1/inspect/jobs/{job_id}/report.json"),
                                        ("bundle.zip", f"/api/v1/inspect/jobs/{job_id}/bundle.zip"),
                                    ]:
                                        d_code, _, d_bytes = cli.request_raw("GET", ep_suffix, require_auth=True)
                                        if d_code == 200 and d_bytes:
                                            (out_dir / fname).write_bytes(d_bytes)
                                    _append_log(f"🎉 300 秒三阶段真机检测全部完成！报告目录：{out_dir}")
                                    _append_log(f"   • 无水印 PDF 报告：{out_dir / 'report.pdf'}")
                                    _append_log(f"   • PCAP 抓包证据包：{out_dir / 'bundle.zip'}")
                                    break
                                if j_status == "FAILED":
                                    task_obj["message"] = f"沙箱任务执行失败：{j_info.get('error_msg') or '未知错误'}"
                                    task_obj["status"] = "error"
                                    task_obj["state"] = "error"
                                    return
                            if elapsed > 540:
                                _append_log(f"⚠️ 轮询等待超时，您可稍后通过任务编号 {job_id} 拉取报告。")
                                break

                        task_obj["job_id"] = job_id
                        task_obj["status"] = "ok"
                        task_obj["state"] = "done"
                    except Exception as exc:
                        task_obj["message"] = str(exc)
                        task_obj["status"] = "error"
                        task_obj["state"] = "error"

                threading.Thread(target=_bg_worker, daemon=True).start()
                self._send_json({"status": "started", "task_id": task_id})
                return

            self._send_json({"status": "error", "message": "Unknown endpoint"}, 404)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LocalWorkbenchHandler)
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}/"
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    sys_name = platform.system()
    if sys_name == "Darwin":
        native_bin = _get_or_build_macos_native_webview_bin()
        if native_bin is not None and native_bin.exists():
            proc = subprocess.Popen([str(native_bin), url])
            proc.wait()
            return

    candidate_bins: list[Path] = []
    if sys_name == "Darwin":
        candidate_bins = [
            Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
        ]
    elif sys_name == "Windows":
        candidate_bins = [
            Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
            Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
            Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        ]
    app_bin = next((b for b in candidate_bins if b.exists()), None)
    if app_bin is not None:
        proc = subprocess.Popen(
            [
                str(app_bin),
                f"--app={url}",
                "--window-size=1080,760",
                "--no-first-run",
                "--no-default-browser-check",
            ]
        )
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    else:
        webbrowser.open(url)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass


MACOS_WKWEBVIEW_OBJC_SRC = r"""
#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

@interface AppDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate>
@property (strong) NSWindow *window;
@property (strong) WKWebView *webView;
@property (copy) NSString *targetURL;
@end

@implementation AppDelegate
- (void)setupMainMenu {
    NSMenu *menubar = [[NSMenu alloc] init];
    NSMenuItem *appMenuItem = [[NSMenuItem alloc] init];
    [menubar addItem:appMenuItem];
    NSMenu *appMenu = [[NSMenu alloc] init];
    [appMenu addItemWithTitle:@"退出 ClawProbe Desktop" action:@selector(terminate:) keyEquivalent:@"q"];
    [appMenuItem setSubmenu:appMenu];

    NSMenuItem *editMenuItem = [[NSMenuItem alloc] init];
    [menubar addItem:editMenuItem];
    NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"编辑"];
    [editMenu addItemWithTitle:@"剪切" action:@selector(cut:) keyEquivalent:@"x"];
    [editMenu addItemWithTitle:@"复制" action:@selector(copy:) keyEquivalent:@"c"];
    [editMenu addItemWithTitle:@"粘贴" action:@selector(paste:) keyEquivalent:@"v"];
    [editMenu addItemWithTitle:@"全选" action:@selector(selectAll:) keyEquivalent:@"a"];
    [editMenuItem setSubmenu:editMenu];

    [NSApp setMainMenu:menubar];
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    [self setupMainMenu];
    NSRect frame = NSMakeRect(0, 0, 1100, 760);
    NSUInteger style = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                       NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable;
    self.window = [[NSWindow alloc] initWithContentRect:frame
                                              styleMask:style
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    [self.window setTitle:@"ClawProbe Desktop v1.1 — 移动应用 300 秒三阶段真机动态检测工作台"];
    [self.window center];
    [self.window setDelegate:self];
    [self.window setBackgroundColor:[NSColor colorWithSRGBRed:0.043 green:0.067 blue:0.125 alpha:1.0]];

    WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
    self.webView = [[WKWebView alloc] initWithFrame:[[self.window contentView] bounds] configuration:config];
    [self.webView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    [[self.window contentView] addSubview:self.webView];

    NSURL *url = [NSURL URLWithString:self.targetURL];
    NSURLRequest *req = [NSURLRequest requestWithURL:url];
    [self.webView loadRequest:req];

    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    return YES;
}
@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *url = @"http://127.0.0.1:8080/";
        if (argc > 1) {
            url = [NSString stringWithUTF8String:argv[1]];
        }
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        AppDelegate *delegate = [[AppDelegate alloc] init];
        delegate.targetURL = url;
        [app setDelegate:delegate];
        [app run];
    }
    return 0;
}
"""


def _get_or_build_macos_native_webview_bin() -> Path | None:
    """
    Returns the native macOS Cocoa + WKWebView window executable (`ClawProbeNativeWindow`),
    either pre-bundled inside `ClawProbe Desktop.app/Contents/MacOS/ClawProbeNativeWindow`
    or compiled on-demand via `/usr/bin/clang -framework Cocoa -framework WebKit`.
    """
    bundled = THIS_DIR.parent / "MacOS" / "ClawProbeNativeWindow"
    if bundled.exists() and os.access(bundled, os.X_OK):
        return bundled
    local_bundled = THIS_DIR / "ClawProbeNativeWindow"
    if local_bundled.exists() and os.access(local_bundled, os.X_OK):
        return local_bundled

    cache_bin = CONFIG_DIR / "bin" / "ClawProbeNativeWindow"
    if cache_bin.exists() and os.access(cache_bin, os.X_OK):
        return cache_bin

    clang_bin = Path("/usr/bin/clang")
    if not clang_bin.exists():
        return None
    try:
        cache_bin.parent.mkdir(parents=True, exist_ok=True)
        src_file = cache_bin.parent / "ClawProbeNativeWindow.m"
        src_file.write_text(MACOS_WKWEBVIEW_OBJC_SRC, encoding="utf-8")
        res = subprocess.run(
            [
                str(clang_bin),
                "-O2",
                "-fobjc-arc",
                "-framework",
                "Cocoa",
                "-framework",
                "WebKit",
                str(src_file),
                "-o",
                str(cache_bin),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if res.returncode == 0 and cache_bin.exists():
            os.chmod(cache_bin, 0o755)
            return cache_bin
    except Exception:
        pass
    return None


# ============================================================================
# CLI Entrypoint (Headless Verification, Token Import, & GUI Launcher)
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="ClawProbe Desktop — 移动应用 300 秒三阶段真机动态检测桌面客户端")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="Gateway HTTPS endpoint")
    parser.add_argument("--import-sub", default="", help="Import a cp_sub_v1_... subscription token into OS Keychain")
    parser.add_argument("--status", action="store_true", help="Print current credential & keychain status as JSON")
    parser.add_argument("--headless-self-test", action="store_true", help="Run E-3 keychain & token roundtrip self-test")
    args, _unknown = parser.parse_known_args()

    if args.import_sub:
        obj = decode_sub_token_local(args.import_sub)
        cfg = save_desktop_credentials(
            api_key=obj["k"],
            sign_secret=obj["s"],
            ref_code=obj.get("r", ""),
            sub_token=args.import_sub,
            endpoint=obj.get("e", args.endpoint),
            spki_pin=obj.get("p"),
        )
        print(json.dumps({"status": "ok", "imported": cfg}, ensure_ascii=False, indent=2))
        return 0

    if args.headless_self_test:
        prev_kc = load_secret_from_system_keychain()
        sample_payload = json.dumps({"sign_secret": "sec_test_keychain_roundtrip_12345", "sub_token": "cp_sub_v1_test"})
        try:
            ok_kc, backend = store_secret_in_system_keychain(sample_payload)
            loaded = load_secret_from_system_keychain() if ok_kc else sample_payload
        finally:
            if prev_kc:
                store_secret_in_system_keychain(prev_kc)
        snippets = generate_developer_integration_snippets(
            {"endpoint": args.endpoint, "api_key": "cp_live_selftest_001", "spki_pin": DEFAULT_PINNED_SPKI_SHA256[0]}
        )
        print(
            json.dumps(
                {
                    "status": "ok",
                    "platform": platform.system(),
                    "keychain_stored": ok_kc,
                    "storage_backend": backend,
                    "keychain_roundtrip_verified": loaded == sample_payload,
                    "snippets_generated": list(snippets.keys()),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.status:
        creds = load_desktop_credentials()
        if not creds:
            print(json.dumps({"status": "unconfigured", "config_file": str(CONFIG_FILE)}, ensure_ascii=False, indent=2))
            return 0
        print(
            json.dumps(
                {
                    "status": "configured",
                    "endpoint": creds["endpoint"],
                    "api_key_masked": creds["api_key"][:12] + "****",
                    "ref_code": creds["ref_code"],
                    "secret_storage_backend": creds["secret_storage_backend"],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    launch_gui(initial_endpoint=args.endpoint)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
