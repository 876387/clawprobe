# ClawProbe APK Analysis API Client (`clawprobe`)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-brightgreen.svg)](https://pypi.org/project/clawprobe/)

**ClawProbe (`clawprobe`)** 是 **ClawProbe 移动应用 APK 深度解析与 300 秒真机动态技术检测平台**（[https://www.atooli.com](https://www.atooli.com)）的官方 Python API 客户端与命令行工具。

基于 **100% Python 标准库（Zero Third-Party Dependencies）** 构建，内置 **HMAC-SHA256 v2 全报文防重放签名** 与 **证书链公钥指纹校验（SPKI Pinning / Embedded CA）**，一行命令或数行 Python 代码即可调用云端 APK 深度解析 API，自动返回包体静态指纹、17 类第三方 SDK 清单、**「用户点击隐私弹窗同意前抢跑联网」** 毫秒级偏移台账、无水印签封 PDF 报告与原始 PCAP 抓包证据包。

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
