# ClawProbe CLI (`clawprobe`)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-brightgreen.svg)](https://pypi.org/project/clawprobe/)

**ClawProbe CLI** 是 **ClawProbe 移动应用 300 秒真机动态技术体检与 CI/CD 隐私门禁平台**（[https://www.atooli.com](https://www.atooli.com)）的官方命令行客户端。

基于 **100% Python 标准库（Zero Third-Party Dependencies）** 构建，内置 **HMAC-SHA256 v2 全报文防重放签名** 与 **证书链公钥指纹校验（SPKI Pinning / Embedded CA）**，开箱即可嵌入 GitHub Actions、GitLab CI、Jenkins 等企业级 DevSecOps 流水线，在每次发版前自动拦截 **「用户点击隐私弹窗同意前抢跑联网」** 等隐私合规隐患。

---

## 核心特性 (Key Features)

1. **零第三方依赖 (Zero External Dependencies)**：仅依赖 Python 3.9+ 标准库（`ssl`、`http.client`、`hashlib`、`hmac`、`json`），无需编译 C 扩展，无第三方供应链依赖风险。
2. **300 秒三阶段真机沙箱时序体检 (300s 3-Stage Live Sandbox Inspection)**：
   - **Stage 1 (`pre_consent` · 0~45s)**：冷启动静默期（未点击隐私弹窗同意前）网络通信五元组、DNS/SNI 与敏感留痕检测；
   - **Stage 2 (`post_consent` · 45~255s)**：点击同意隐私弹窗后 UI 自动化遍历与第三方 SDK 加密框架清单盘点；
   - **Stage 3 (`background` · 255~300s)**：退后台静默期心跳、唤醒、静默上传与高损耗 UDP/PCDN 传输行为观测。
3. **CI/CD 确定性退出码门禁 (Deterministic Exit Codes)**：通过 `--fail-on-preconsent` 自动阻断存在未同意前抢跑通信的构建任务（返回 `Exit Code 2`）。
4. **队列拥塞智能指数退避 (Smart Queue Backoff)**：高并发场景下遇 `HTTP 429 (ERR_P0_HOT_SPARE_BUSY)` 自动在 `--queue-timeout` 窗口内指数退避重试，保障夜间流水线稳定收敛。
5. **一键 3 遍覆写物理销毁 (`--reclaim`)**：下载完本地 PDF/JSON/ZIP 证据包后，支持在流水线末尾自动触发云端工件 3 遍覆写物理清零并返回 SHA-256 销毁回执。

---

## 快速安装 (Installation)

推荐使用 `pipx` 或 `pip` 直接从官方 PyPI 安装：

```bash
# 推荐：使用 pipx 隔离安装全局命令（含官方 PEP 503 高速镜像源，国内 20ms 直连）
pipx install --pip-args="--extra-index-url https://www.atooli.com/simple" clawprobe

# 或使用 pip 安装
pip install -U --extra-index-url https://www.atooli.com/simple clawprobe

# 也可直接从 GitHub Release 安装
pip install -U https://github.com/876387/clawprobe/releases/download/v1.3.0/clawprobe-1.3.0-py3-none-any.whl
```

安装完成后，可执行一键环境与链路自检（无需 API Key）：

```bash
clawprobe doctor
```

---

## 快速上手 (Quick Start)

### 1. 配置访问凭据

前往 [ClawProbe 官网工作台 (https://www.atooli.com)](https://www.atooli.com) 申请试用或生产凭据后，配置环境变量或执行 `auth login`：

```bash
# 方式 A：环境变量（适合 CI/CD 流水线）
export CLAW_API_KEY="cnx_live_your_key_id"
export CLAW_API_SECRET="sec_your_hmac_secret"

# 方式 B：本地持久化登录（权限自动锁定为 0600）
clawprobe auth login --api-key cnx_live_your_key_id --secret sec_your_hmac_secret

# 验证鉴权与当前剩余额度
clawprobe auth verify
```

### 2. 提交 APK 并启用发版前隐私门禁

```bash
clawprobe analyze ./app-release.apk \
  --attest-authorized \
  --mode privacy \
  --fail-on-preconsent \
  --queue-timeout 900 \
  --out ./clawprobe-report.pdf \
  --json-out ./clawprobe-report.json \
  --reclaim
```

- 若检测完成且 **Stage 1（未同意隐私政策前）** 未发现抢跑外联，命令返回 `Exit Code 0`，并将结构化 JSON 与中英双语 PDF 技术体检报告写入本地。
- 若发现未同意前抢跑外联，命令在终端打印 `[FL-xxxx]` 证据锚点摘要并返回 `Exit Code 2`，直接阻断 CI 发版流水线。

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

## CI/CD 退出码规范 (Exit Codes)

| Exit Code | 含义 (Meaning) | 触发场景 (Scenario) |
| :--- | :--- | :--- |
| `0` | **PASS (合规通过)** | 任务完成，且未触发 `--fail-on-preconsent` 门禁条件 |
| `1` | **USAGE_OR_AUTH_ERROR (参数/鉴权异常)** | 参数缺失、未勾选 `--attest-authorized`、API Key 或 HMAC 签名错误 |
| `2` | **PRIVACY_GATE_TRIGGERED (门禁拦截)** | 启用 `--fail-on-preconsent` 时，检测到同意隐私政策前发生抢跑联网行为 |
| `3` | **QUOTA_EXCEEDED (配额/包名超限)** | 检测额度耗尽 (`ERR_QUOTA_EXCEEDED`) 或超出账号绑定的包名上限 |
| `4` | **NETWORK_OR_QUEUE_TIMEOUT (网络/排队超时)** | 网络不可达、SPKI 证书指纹校验失败或超过 `--queue-timeout` 等待窗口 |

---

## CI/CD 流水线集成模板 (CI/CD Templates)

仓库内置开箱即用的流水线模板，可直接复制到您的工程中：

- **GitHub Actions**：[`ci-templates/github/privacy-gate.yml`](./ci-templates/github/privacy-gate.yml)
- **GitLab CI**：[`ci-templates/gitlab/.gitlab-ci.yml`](./ci-templates/gitlab/.gitlab-ci.yml)
- **结构化报告样卷**：[`samples/sample_report.json`](./samples/sample_report.json)

---

## 合规与安全声明 (Compliance & Security Notice)

1. **合法授权使用**：用户仅可上传并检测其拥有合法著作权或已获明确书面授权的自有 Android 应用包（APK），调用时须显式传入 `--attest-authorized`。
2. **客观技术留痕**：本工具及云端沙箱输出的检测报告仅客观记录特定运行环境与特定时间窗口内的网络通信五元组、TLS 握手特征及第三方 SDK 特征留痕（`[FL-xxxx]` 锚点），供研发与安全团队开展内部合规自查，不构成任何法律意见或行政/司法鉴定结论。
3. **开源许可**：本命令行客户端（`clawprobe`）采用 [Apache-2.0 License](./LICENSE) 开源发布。

---

- **官方网站与在线免登录快检**：[https://www.atooli.com](https://www.atooli.com)
- **问题反馈 (Issues)**：[https://github.com/876387/clawprobe/issues](https://github.com/876387/clawprobe/issues)
