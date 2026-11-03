# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.3.x   | :white_check_mark: |
| < 1.3   | :x:                |

## Security Architecture of `clawprobe`

1. **Zero Third-Party Runtime Dependencies**: `clawprobe` uses exclusively the Python 3.10+ standard library (`ssl`, `hmac`, `hashlib`, `http.client`, `urllib.parse`), eliminating supply-chain risks from transitive PyPI packages.
2. **TLS 1.3 + Certificate Chain & SPKI Verification**: Enforces `TLSv1.3` minimum protocol version with embedded DigiCert Root/Intermediate CA trust anchors and configurable SPKI SHA-256 pinning (`--pin-mode ca|strict`).
3. **Canonical Full-Body HMAC-SHA256 v2 Anti-Replay**: Signs `METHOD\npath?sorted_query\ntimestamp\nnonce\nsha256(full_raw_http_body)` with a `±60s` clock-skew window and single-use cryptographic nonces.
4. **Immediate Evidence Reclamation (`--reclaim`)**: Supports immediate 3-pass physical overwrite (`shred`) of cloud sandbox artifacts upon report download.

## Reporting a Vulnerability

Please report security issues privately via email to `876387@gmail.com` with subject `[SECURITY] clawprobe` rather than opening a public issue. We respond within 24 hours.
