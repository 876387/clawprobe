# Changelog

## [1.3.5-v6.2-90pct-compat] - 2026-11-18

### Cloud Engine Seamless Upgrade (`v6.2-90pct-20261118`)
- Transitioned the cloud dual-tower attribution & 17-class third-party SDK decoupling baseline to `v6.2-90pct-20261118` (`467,520` known apps, `1,142,318` purified SubCenter anchors, `99.17%` 17-class SDK Micro accuracy).
- Guaranteed 100% zero-breaking-change backward compatibility for all historical `clawprobe v1.0.0 ~ v1.3.5` CLIs, `clawprobe diff` remediation comparison workflows, GitHub Actions CI gates, and `clawprobe-desktop` GUI clients without requiring client re-installation or credential re-binding.

## [1.3.2] - 2026-11-05

### Added
- Integrated the Open-Source Cross-Platform Desktop GUI Reference Demo (`desktop_client/` & `src/clawprobe/desktop.py`) directly into the `clawprobe` CLI package and wheel distribution (`clawprobe desktop` subcommand and `clawprobe-desktop` console entrypoint).
- Added native macOS Cocoa + `WKWebView` Universal (`arm64` + `x86_64`) window host in `desktop_client/build_macos_dmg.py` and Windows x64 PyInstaller packaging script in `desktop_client/build_windows_exe.py`.
- Added SHA-256 content-addressed instant deduplication ("秒传", 0-byte upload when server-side 24h CAS matches) and 300 MB chunked streaming upload across `ClawNexusClient`, `clawprobe analyze`, and `ClawProbe Desktop`.
- Added OS Keychain credential storage (`MACOS_KEYCHAIN` via `/usr/bin/security` and `WINDOWS_PASSWORD_VAULT` via PowerShell `PasswordVault`) with automatic synchronization to `~/.clawnexus/credentials.json`.

## [1.3.1] - 2026-11-02

### Security & Compatibility
- Enforced strict client-only boundary audit across `src/`, `samples/`, and documentation to guarantee zero internal backend or sandbox implementation details are exposed.
- Lowered `requires-python` to `>=3.9` for out-of-the-box compatibility with macOS system Python 3.9 and Linux servers.

## [1.3.0] - 2026-11-02

### Added
- Standalone zero-dependency PyPI package (`pip install clawprobe` / `pipx run clawprobe`).
- Default official HTTPS endpoint `https://www.atooli.com` with embedded DigiCert Root & Intermediate CA bundle (`Encryption Everywhere DV TLS CA - G2` & `DigiCert Global Root G2`) and certificate-renewal-safe `ca` pin mode (`--pin-mode ca|strict|off`).
- `clawprobe doctor` diagnostic command (checks Python/OpenSSL TLS 1.3, certificate chain, SPKI fingerprint, `±60s` clock skew, and `0600` credential file permissions).
- Automatic exponential-backoff queue retry (`--queue-timeout 900`) when clean sandbox slots return `HTTP 429`.
- Structured exit codes (`0` pass, `1` auth/usage error, `2` pre-consent alert, `3` quota/package limit exceeded, `4` network/queue timeout).
