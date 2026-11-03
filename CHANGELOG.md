# Changelog

## [1.3.1] - 2026-11-02

### Security & Compatibility
- Enforced strict client-only boundary audit across `src/`, `samples/`, `examples/`, and documentation to guarantee zero internal backend or sandbox implementation details are exposed.
- Lowered `requires-python` to `>=3.9` for out-of-the-box compatibility with macOS system Python 3.9 and enterprise CI runners.

## [1.3.0] - 2026-11-02

### Added
- Standalone zero-dependency PyPI package (`pip install clawprobe` / `pipx run clawprobe`).
- Default official HTTPS endpoint `https://www.atooli.com` with embedded DigiCert Root & Intermediate CA bundle (`Encryption Everywhere DV TLS CA - G2` & `DigiCert Global Root G2`) and certificate-renewal-safe `ca` pin mode (`--pin-mode ca|strict|off`).
- `clawprobe doctor` diagnostic command (checks Python/OpenSSL TLS 1.3, certificate chain, SPKI fingerprint, `±60s` clock skew, and `0600` credential file permissions).
- Automatic exponential-backoff queue retry (`--queue-timeout 900`) when clean sandbox slots return `HTTP 429 ERR_P0_HOT_SPARE_BUSY`.
- Granular CI/CD exit codes (`0` pass, `1` auth/usage error, `2` pre-consent privacy gate triggered, `3` quota/package limit exceeded, `4` network/queue timeout).
- Ready-to-use GitHub Actions (`ci-templates/github/privacy-gate.yml`) and GitLab CI (`ci-templates/gitlab/.gitlab-ci.yml`) templates.
