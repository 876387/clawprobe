# Changelog

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
