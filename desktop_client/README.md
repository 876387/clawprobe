# ClawProbe Desktop (Windows & macOS) — 开源 CLI 图形化参考工作台 (GUI Reference Demo)

> **定位说明**：
> `desktop_client/` 是基于 **`clawprobe` 开源零依赖 CLI/SDK (`Apache-2.0`)** 构建的**官方跨平台桌面图形化参考实现（Reference GUI Demo）**，同时支持 **Windows 10/11 (x64)** 与 **macOS 12+ (Apple Silicon / Intel)**。
> 开发者与安全合规团队既可以直接运行本桌面工作台完成免命令行「选包即检、扫码/卡密激活、自动导出 PDF+PCAP」，也可以直接参考或 Fork 本目录源码，将其二次开发、定制为您团队内部的移动应用合规自检桌面工具。

---

## 一、 核心架构特性（0 第三方依赖 · 纯 Python 标准库）

1. **复用 `clawprobe.client.ClawNexusClient` 核心通信层**：
   - 底层 100% 复用开源 CLI 的 TLS 1.3 + SPKI 公钥指纹钉扎与 `HMAC-SHA256 v2` 规范化签名引擎（见 [`src/clawprobe/client.py`](../src/clawprobe/client.py)）。
2. **原生系统安全钥匙串（System Keychain）优先存储**：
   - **macOS (`Darwin`)**：通过 `/usr/bin/security add-generic-password` 将 `sign_secret` 与订阅串加密存入 **macOS 钥匙串 (`MACOS_KEYCHAIN`)**；
   - **Windows (`Windows`)**：通过 PowerShell `Windows.Security.Credentials.PasswordVault` 存入 **Windows 凭据管理器 (`WINDOWS_PASSWORD_VAULT`)**；
   - **Linux / 降级兜底**：`~/.clawprobe/config.json`（强制 `0600` 权限），并自动同步至 `~/.clawnexus/credentials.json`，实现 **桌面版 Demo 与 `clawprobe` 命令行工具凭据无缝互通**。
3. **跨平台本地回环引擎 (`127.0.0.1`) + 原生独立窗口 (`--app=`)**：
   - 彻底规避 macOS 系统内置旧版 `Tcl/Tk 8.5.9` 暗色模式空白窗口缺陷；
   - 启动时在 `127.0.0.1:<随机空闲端口>` 开启仅本机可访问的轻量级 Loopback 服务，并自动拉起 macOS (`Google Chrome` / `Microsoft Edge`) 或 Windows (`msedge.exe` / `chrome.exe`) 的 `--app=` 独立原生应用窗口；
   - 支持系统原生文件选择器（macOS `osascript` / Windows `System.Windows.Forms.OpenFileDialog`）与手动路径粘贴双模式。

---

## 二、 三种直接运行与二次开发方式

### 方式 1：安装 `clawprobe` 后通过 CLI 子命令一键启动（推荐开发者）
```bash
pip install -U clawprobe
clawprobe desktop
# 或直接运行独立入口命令：
clawprobe-desktop
```

### 方式 2：直接运行跨平台单文件源码脚本（免打包、方便二次修改）
```bash
# 在仓库根目录下直接运行（Windows / macOS / Linux 通用）
python3 desktop_client/clawprobe_desktop.py

# 查看当前凭据与系统钥匙串状态
clawprobe desktop --status

# 运行系统钥匙串与代码片段生成自检
clawprobe desktop --headless-self-test
```

### 方式 3：自行打包 macOS `.dmg` 或 Windows `.exe` 独立发行版
- **macOS 打包原生 Cocoa `WKWebView` Universal `.app` 与 `.dmg` 镜像**（使用 macOS 原生 `clang` + `hdiutil`）：
  ```bash
  python3 desktop_client/build_macos_dmg.py
  # 产物输出至：desktop_client/dist/ClawProbe-Desktop-macOS.dmg
  ```
- **Windows 10/11 (x64) 打包单文件 `.exe`**（使用 `build_windows_exe.py` 或仓库 `.github/workflows/build-desktop-win64.yml`）：
  ```powershell
  pip install pyinstaller
  python desktop_client/build_windows_exe.py
  # 产物输出至：desktop_client/dist/ClawProbe-Desktop-Win64.exe
  ```

---

## 三、 目录文件清单

| 文件名 | 说明 |
| :--- | :--- |
| [`clawprobe_desktop.py`](./clawprobe_desktop.py) | 跨平台（Windows / macOS）桌面工作台完整单文件参考实现（含 300 MB 大包上传、SHA-256 极速秒传、系统钥匙串、扫码轮询、卡密兑换、16 位恢复码、30s 快检与 300s 完整真机检测） |
| [`../src/clawprobe/desktop.py`](../src/clawprobe/desktop.py) | 集成在 `clawprobe` PyPI/Wheel 包内的 `clawprobe desktop` 子命令模块 |
| [`build_macos_dmg.py`](./build_macos_dmg.py) | macOS Universal (`arm64` + `x86_64`) 原生 `WKWebView` `.app` 应用包与 `.dmg` 磁盘镜像构建脚本 |
| [`build_windows_exe.py`](./build_windows_exe.py) | Windows 10/11 (x64) `ClawProbe-Desktop-Win64.exe` 单文件打包与 SHA-256 生成脚本 |
| [`UNSIGNED_INSTALL_GUIDE.md`](./UNSIGNED_INSTALL_GUIDE.md) | 未捆绑商业代码签名证书（Unsigned）版本的 macOS Gatekeeper / Windows SmartScreen 放行指引 |
| [`../.github/workflows/build-desktop-win64.yml`](../.github/workflows/build-desktop-win64.yml) | GitHub Actions 自动构建 `ClawProbe-Desktop-Win64.exe` 并校验 SHA-256 的 CI 工作流参考 |
