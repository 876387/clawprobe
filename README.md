# JanusFlow · 雅努斯流 (`janusflow.cn` · `JanusFlow.net` · `atooli.com` · ClawProbe CLI & Desktop GUI)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-brightgreen.svg)](https://pypi.org/project/clawprobe/)

**JanusFlow（中文名：雅努斯流 / 双面神流 · 官方品牌域名：`janusflow.cn` / `JanusFlow.net` / `atooli.com` · 原 ClawProbe `clawprobe`）** 是基于 **Joint Anchor Network for Ultra-Scale Flow Identification（双塔解耦加密流表征 + 两阶段开集门神拒识引擎）** 构建的 **移动应用 APK 深度解析与 300 秒真机动态技术检测平台**（官方品牌域名矩阵：`janusflow.cn` · `JanusFlow.net` · [https://www.atooli.com](https://www.atooli.com)）的官方开源 Python API 客户端、命令行工具（`janusflow` / `clawprobe`）与跨平台图形化桌面端参考实现（`janusflow-desktop` / `clawprobe-desktop`）。

> **品牌核心寓意（JanusFlow · 雅努斯流）**：
> 雅努斯（Janus）是古罗马神话中的“双面守护门神”，一面洞察过去、一面注视未来，且掌管“门禁（Gate）”。完美契合本系统两大核心架构：
> 1. **双面（双塔解耦 · Dual-Tower）**：一面看传输层序列动态（Sequence Tower · 侧信道视角），一面看脱敏握手字节（Byte Tower · 网关视角）；
> 2. **门神（两阶段开集拒识门控 · Two-Stage Cascade Gate）**：守住网关边界，放行库内已知应用，精准拒识库外未知 OOD 流量与共享第三方 SDK 误报。

基于 **100% Python 标准库（Zero Third-Party Dependencies）** 构建，内置 **HMAC-SHA256 v2 全报文防重放签名**、**SHA-256 内容寻址 24 小时极速秒传（0 字节免重复上传）** 与 **证书链公钥指纹校验（SPKI Pinning / Embedded CA）**，一行命令或数行 Python 代码即可调用云端 APK 深度解析 API，自动返回包体静态指纹、17 类第三方 SDK 清单、**「用户点击隐私弹窗同意前抢跑联网」** 毫秒级偏移台账、无水印签封 PDF 报告与原始 PCAP 抓包证据包。

---

## 核心特性 (Key Features)

1. **零第三方依赖 (Zero External Dependencies)**：仅依赖 Python 3.9+ 标准库（`ssl`、`http.client`、`hashlib`、`hmac`、`json`），无需编译 C 扩展，无第三方供应链依赖风险。
2. **APK 静态解析 + 300 秒三阶段动态检测 API**：
   - **Stage 1 (`pre_consent` · 0~60s)**：冷启动静默期（未点击隐私弹窗同意前）网络通信五元组、DNS/SNI 与抢跑联网检测；
   - **Stage 2 (`post_consent` · 60~180s)**：点击同意隐私弹窗后 UI 自动化遍历与第三方 SDK 加密框架清单盘点；
   - **Stage 3 (`background` · 180~300s)**：退后台息屏静默期高频心跳、后台保活唤醒与静默数据上传行为观测。
3. **标准结构化返回产物**：支持一键导出 `report.json`（完整结构化 APK 解析数据）、`report.pdf`（中英双语技术检测报告）与 `bundle.zip`（含原始 PCAP 抓包与 SHA-256 校验清单）。
4. **队列拥塞智能指数退避 (Smart Queue Backoff)**：高并发场景下遇 `HTTP 429` 自动在 `--queue-timeout` 窗口内指数退避重试。
5. **一键 3 遍覆写物理销毁 (`--reclaim`)**：下载完本地 PDF/JSON/ZIP 证据包后，支持自动触发云端工件 3 遍覆写物理清零并返回 SHA-256 销毁回执。

---

## 快速安装 (Installation)

推荐使用 `pipx` 或 `pip` 直接从官方 PyPI 安装：

```bash
# 方式 A：使用 pipx 隔离安装全局命令
pipx install clawprobe

# 方式 B：使用 pip 安装
pip install -U clawprobe
```

安装完成后，可执行一键环境与 API 链路自检（无需 API Key）：

```bash
clawprobe doctor
```

---

## 快速上手 (Quick Start)

### 1. 配置 API 访问凭据

前往 [ClawProbe 官网工作台 (https://www.atooli.com)](https://www.atooli.com) 申请体验或购买按量/包月 APIKey 后，配置环境变量或执行 `auth login`：

```bash
# 方式 A：环境变量配置
export CLAW_API_KEY="cnx_live_your_key_id"
export CLAW_API_SECRET="sec_your_hmac_secret"

# 方式 B：本地持久化登录（权限自动锁定为 0600）
clawprobe auth login --api-key cnx_live_your_key_id --secret sec_your_hmac_secret

# 验证鉴权与当前剩余额度
clawprobe auth verify
```

### 2. 调用 APK 深度解析与 300s 动态检测 API

```bash
clawprobe analyze ./app-release.apk \
  --attest-authorized \
  --mode privacy \
  --queue-timeout 900 \
  --out ./clawprobe-report.pdf \
  --json-out ./clawprobe-report.json \
  --bundle ./clawprobe-bundle.zip \
  --reclaim
```

### 3. 查询历史任务与手动物理销毁云端工件

```bash
# 查询任务并下载完整 ZIP 证据包（含 PDF + JSON + PCAP + SHA256 清单）
clawprobe job <job_id> \
  --out ./report.pdf \
  --json-out ./report.json \
  --bundle ./evidence-bundle.zip

# 立即触发云端任务工件 3 遍覆写物理销毁
clawprobe reclaim <job_id>
```

### 4. 开源跨平台桌面工作台参考实现 (Windows & macOS Desktop GUI Demo)

本仓库已将基于 `ClawNexusClient` 构建的 **Windows 10/11 & macOS 12+ 跨平台桌面图形化参考实现 (`Apache-2.0`)** 完整整合进 `clawprobe` CLI 服务包（[`src/clawprobe/desktop.py`](./src/clawprobe/desktop.py) 与 [`desktop_client/`](./desktop_client/)），供社区开发者直接免命令行启动使用，或作为企业内部合规自检桌面工具二次开发参考：

- **核心特性**：
  - **0 第三方依赖 + 原生窗口容器**：纯 Python 标准库实现本地 `127.0.0.1` 回环工作台；macOS DMG 采用原生 Cocoa + `WKWebView` Universal (`arm64` + `x86_64`) 独立原生窗口（不唤醒外部浏览器标签页），Windows/源码模式自动适配 `Edge`/`Chrome` `--app=` 独立窗口；
  - **300 MB 大包流式上传 + SHA-256 极速秒传**：支持最大 `300 MB` 单 APK 分块流式上传；上传前自动比对本地与云端 24 小时内容寻址池 (`cas_24h`) 的 64 位 `SHA-256` 指纹，命中一致文件时 **0 字节免传秒级进入真机沙箱**；
  - **系统安全钥匙串优先**：自动将 `sign_secret` 与订阅串存入 **macOS Keychain (`MACOS_KEYCHAIN`)** 或 **Windows 凭据管理器 (`WINDOWS_PASSWORD_VAULT`)**，并与 CLI 凭据 (`~/.clawnexus/credentials.json`) 双向自动同步；
  - **全流程闭环**：支持原生文件选择、免费 30 秒抢跑快检、完整 300 秒三阶段真机检测（自动导出无水印 `PDF + JSON + PCAP 证据包`）、端内微信/支付宝扫码秒开与卡密 (`CP-...`) / 恢复码 (`RCV-...`) 激活。

```bash
# 方式 A：安装 clawprobe 后通过 CLI 子命令或独立入口一键启动桌面工作台 Demo
janusflow desktop
# 或直接执行：
janusflow-desktop

# 方式 B：直接运行跨平台单文件源码脚本（支持 Windows / macOS 二次开发定制）
python3 desktop_client/clawprobe_desktop.py

# 方式 C：本地自行打包 macOS .dmg 或 Windows .exe 独立桌面发行版
python3 desktop_client/build_macos_dmg.py      # 输出 desktop_client/dist/ClawProbe-Desktop-macOS.dmg
python3 desktop_client/build_windows_exe.py    # 输出 desktop_client/dist/ClawProbe-Desktop-Win64.exe
```

详细架构与二次开发说明见：[`desktop_client/README.md`](./desktop_client/README.md)。

---

## 双塔加密流量在线识别与两类开源硬件探针接入 (`FlowSketch v2` + `OpenWrt` / `10G TAP`)

除移动应用 APK 活体动态分析外，`janusflow` (`clawprobe`) 同时提供完整的 **双塔（序列塔 Track A + 字节塔 Track B）免解密加密流量识别、两阶段门神 OOD 开集拒识与 PCDN 多子网分片上行拓扑检测 CLI 服务**，并针对**边侧软路由**与**核心网万兆分光**开源了两套标准探针接入套件：

| 探针形态 | 适用场景 | 核心技术特征 | 开源目录与部署指南 |
| :--- | :--- | :--- | :--- |
| **方案 A：边侧 OpenWrt 软路由 / 企业分支网关轻量探针** | 园区出口软路由、分支机构 OpenWrt 网关（x86_64 / ARM64 MT798x / R2S/R4S/R5S） | - 仅截每包前 `256B` 头部写入 `/var/run/janusflow` 内存目录（**0 闪存磨损**）；<br/>- 本地 **FlowSketch v2 (`2.0-pa`)** `100x` 压缩为 `.v2.fsk.jsonl.gz`（原始载荷不出内网）；<br/>- 自动解封装 `PPPoE Session` 与 `802.1Q VLAN`，支持融合 `/proc/net/nf_conntrack` 字节计数。 | [`probes/openwrt_edge/`](./probes/openwrt_edge/README.md)<br/>- [`openwrt_probe_agent.py`](./probes/openwrt_edge/openwrt_probe_agent.py)<br/>- [`janusflow-probe.init`](./probes/openwrt_edge/janusflow-probe.init)<br/>- [`install_openwrt_probe.sh`](./probes/openwrt_edge/install_openwrt_probe.sh) |
| **方案 B：核心网 10G / 40G 光纤分光器 (Optical TAP) / 交换机 SPAN 镜像探针** | 运营商城域网汇聚、高校万兆出口、政企核心交换机无源光纤分光或 ERSPAN/SPAN 旁路服务器 | - 一键锁定万兆镜像口 `promisc on arp off` 与 `ethtool -K tso/gso/gro/lro off` + 对称 Toeplitz RSS 队列哈希；<br/>- 自动解封装 **单/双层 VLAN (QinQ)** 与 **VXLAN (UDP 4789)**；<br/>- 内置 **单遍自适应 TCP MSS 估计 (`est_mss`) 与 `>1500B` 超大帧折叠还原引擎**，消除虚拟交换机 GRO 失真。 | [`probes/core_10g_tap/`](./probes/core_10g_tap/README.md)<br/>- [`tune_10g_tap_nic.sh`](./probes/core_10g_tap/tune_10g_tap_nic.sh)<br/>- [`core_10g_tap_agent.py`](./probes/core_10g_tap/core_10g_tap_agent.py)<br/>- [`janusflow-10g-tap@.service`](./probes/core_10g_tap/janusflow-10g-tap@.service) |

### 1. 离线/在线 FlowSketch v2 提纯、双塔应用识别与 PCDN 拓扑扫描命令

```bash
# ① 本地将数百 MB 的原始 PCAP/PCAPNG 提纯压缩为几百 KB 的 FlowSketch v2 (.v2.fsk.jsonl.gz)
janusflow sketch ./capture.pcap -o ./capture.v2.fsk.jsonl.gz

# ② 调用云端 JanusFlow 双塔引擎识别加密应用（58,592 库内应用 + 两阶段 OOD 门神拒识 + 17 类 SDK）
janusflow profile ./capture.v2.fsk.jsonl.gz \
  --device-id office-openwrt-01 \
  --local-cidr 10.0.0.0/8 \
  --format table

# ③ 调用多子网分片分发类 PCDN 拓扑与上下行包络扫描（大于 6MB 的 PCAP 会自动在本地先转 FlowSketch）
janusflow pcdn-scan ./campus_egress.pcap.gz \
  --device-id campus-10g-tap01 \
  --local-cidr 10.0.0.0/8,100.64.0.0/10 \
  --local-sketch \
  --format table

# ④ 查询探针设备过去 1 小时的应用活跃时间线或 PCDN 异常终端时间线
janusflow timeline --device-id office-openwrt-01 --window 3600 --format table
janusflow timeline --device-id campus-10g-tap01 --window 3600 --pcdn-only --format table
```

### 2. 一行命令启动边侧 OpenWrt 探针或核心网 10G 分光探针守护

```bash
# 方式 A：在边侧 OpenWrt / Linux 网关上启动连续 60s 时间窗探针
janusflow probe-openwrt \
  --iface br-lan \
  --device-id openwrt-branch-01 \
  --local-cidr 10.0.0.0/8 \
  --interval 60 \
  --mode both

# 方式 B：在核心网 10G 分光镜像服务器上启动高吞吐探针（自动校验并关闭网卡 TSO/GSO/GRO）
sudo -E janusflow probe-10g-tap \
  --iface eth1 \
  --device-id core-tap-10g-01 \
  --local-cidr 10.0.0.0/8,100.64.0.0/10 \
  --interval 30 \
  --ring-mb 256 \
  --enforce-offload-off \
  --mode both
```

---

## 状态退出码说明 (Exit Codes)

| Exit Code | 含义 (Meaning) | 触发场景 (Scenario) |
| :--- | :--- | :--- |
| `0` | **SUCCESS (解析完成)** | APK 解析与动态检测完成，报告已成功保存 |
| `1` | **USAGE_OR_AUTH_ERROR (参数/鉴权异常)** | 参数缺失、未勾选 `--attest-authorized`、API Key 或 HMAC 签名错误 |
| `2` | **PRECONSENT_ALERT (发现同意前抢跑联网)** | 启用 `--fail-on-preconsent` 时，检测到同意隐私政策前发生抢跑联网行为 |
| `3` | **QUOTA_EXCEEDED (配额/包名超限)** | 检测额度耗尽 (`ERR_QUOTA_EXCEEDED`) 或超出账号绑定的包名上限 |
| `4` | **NETWORK_OR_QUEUE_TIMEOUT (网络/排队超时)** | 网络不可达、证书指纹校验失败或超过 `--queue-timeout` 等待窗口 |

---

## 结构化报告样卷 (Sample JSON Output)

- **完整 JSON 解析报告样卷**：[`samples/sample_report.json`](./samples/sample_report.json)

---

## 合规与安全声明 (Compliance & Security Notice)

1. **合法授权使用**：用户仅可上传并检测其拥有合法著作权或已获明确书面授权的自有 Android 应用包（APK），调用时须显式传入 `--attest-authorized`。
2. **客观技术留痕**：本工具及云端沙箱输出的检测报告仅客观记录特定运行环境与特定时间窗口内的网络通信五元组、TLS 握手特征及第三方 SDK 特征留痕（`[FL-xxxx]` 锚点），供研发与安全团队开展内部合规自查，不构成任何法律意见或行政/司法鉴定结论。
3. **开源许可**：本 API 客户端（`clawprobe`）采用 [Apache-2.0 License](./LICENSE) 开源发布。

---

- **官方网站与在线免登录快检**：[https://www.atooli.com](https://www.atooli.com)
- **问题反馈 (Issues)**：[https://github.com/876387/clawprobe/issues](https://github.com/876387/clawprobe/issues)
