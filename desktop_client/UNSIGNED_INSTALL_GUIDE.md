# ClawProbe Desktop 桌面工作台安装与系统放行指南（未签名版诚实说明）

> **重要提示（Opus E-1 合规声明）**：
> - **第一推荐入口（零安装、零拦截）**：直接通过浏览器访问 **[https://www.atooli.com/#workbench](https://www.atooli.com/#workbench)** 在线网页版工作台，支持免注册拖拽 `.apk` 快检、扫码/卡密秒级解锁完整 300 秒三阶段真机报告、在线下载 PDF/JSON/PCAP 证据包。
> - **第二备选入口（本地桌面客户端）**：当前公测期提供的 `ClawProbe-Desktop-macOS.dmg` 与 `ClawProbe-Desktop-Win64.exe` 为**未捆绑商业代码签名证书（Unsigned）**的原生独立程序。首次启动时，macOS Gatekeeper 或 Windows SmartScreen 会弹出常规安全确认，请按下方 2 步图文指引放行，或直接使用 `pip install` 命令行方式运行。

---

## 一、 发行包 SHA-256 校验值公示

| 平台与发行包 | 下载路径 | SHA-256 校验值 |
| :--- | :--- | :--- |
| **macOS 桌面安装包 (`.dmg`)** | `/download/ClawProbe-Desktop-macOS.dmg` | `ec7252d078f170c729307bd2b0464897b92a2ba6f2b5e718ca18a1d2b6318811` |
| **跨平台 Python 桌面脚本 (`.py`)** | `/download/clawprobe_desktop.py` | 见官网下载卡片实时计算值 |
| **官方零依赖 CLI 套件 (`.whl`)** | `/download/clawprobe-1.3.1-py3-none-any.whl` | 见官网下载卡片实时计算值 |

---

## 二、 macOS (Apple Silicon / Intel) 首次打开放行步骤

1. **方式 A（鼠标右键 2 步放行）**：
   - 双击挂载 `ClawProbe-Desktop-macOS.dmg`，将 `ClawProbe Desktop.app` 拖入「应用程序 (`/Applications`)」；
   - 按住键盘 **`Control` 键** 并鼠标右键点击 `ClawProbe Desktop.app` 图标 $\rightarrow$ 选择 **「打开 (Open)」** $\rightarrow$ 在弹出对话框中点击 **「仍要打开 (Open Anyway)」** 即可永久放行。
2. **方式 B（终端一行命令放行）**：
   ```bash
   xattr -cr "/Applications/ClawProbe Desktop.app" && open "/Applications/ClawProbe Desktop.app"
   ```

---

## 三、 Windows 10 / 11 (x64) 首次打开放行步骤

1. 下载 `ClawProbe-Desktop-Win64.exe` 后双击运行；
2. 若弹出蓝色「Windows 已保护你的电脑 (Microsoft Defender SmartScreen)」提示窗：
   - 第 1 步：点击提示文字下方的 **「更多信息 (More info)」**；
   - 第 2 步：点击右下角出现的 **「仍要运行 (Run anyway)」** 按钮即可正常进入桌面工作台。
