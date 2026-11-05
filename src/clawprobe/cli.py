#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
`clawprobe` — Mobile Application APK Deep Analysis & 300s Live Dynamic Technical Inspection API Client:
  - `clawprobe doctor`
  - `clawprobe auth login --api-key cnx_live_xxx --secret sec_xxx [--endpoint https://www.atooli.com]`
  - `clawprobe auth verify`
  - `clawprobe analyze ./app.apk --attest-authorized --mode privacy --reclaim --out ./report.pdf`
  - `clawprobe job <job_id> [--out ./report.pdf] [--json-out ./report.json] [--bundle ./bundle.zip] [--reclaim]`
  - `clawprobe reclaim <job_id>`

Exit Codes:
  - `0`: Completed cleanly (and 0 Stage-1 pre-consent flows when `--fail-on-preconsent` is set)
  - `1`: Usage, argument, file-not-found, or authentication/attestation error
  - `2`: Pre-consent alert triggered (`--fail-on-preconsent` set and Stage-1 pre-consent flows detected)
  - `3`: Quota or bound-package limit exceeded (`ERR_QUOTA_EXCEEDED` / `ERR_PACKAGE_QUOTA_EXCEEDED`)
  - `4`: Network, service unavailability, or sandbox queue timeout
"""

from __future__ import annotations

import argparse
import email.utils
import json
import os
import ssl
import stat
import sys
import time
from pathlib import Path

from clawprobe import __version__
from clawprobe.client import (
    CRED_PATH,
    DEFAULT_PUBLIC_ENDPOINT,
    ClawNexusClient,
    load_credentials,
    save_credentials,
)


def _build_client(args: argparse.Namespace) -> ClawNexusClient:
    creds = load_credentials(
        endpoint=getattr(args, "endpoint", None),
        api_key=getattr(args, "api_key", None),
        sign_secret=getattr(args, "secret", None),
        spki_pin=getattr(args, "spki_pin", None),
    )
    return ClawNexusClient(
        endpoint=creds["endpoint"],
        api_key=creds["api_key"],
        sign_secret=creds["sign_secret"],
        ca_cert=getattr(args, "ca_cert", None),
        spki_pins=creds["spki_pins"],
        pin_mode=getattr(args, "pin_mode", None),
        timeout=60.0,
    )


def _run_doctor(client: ClawNexusClient) -> int:
    checks: dict = {
        "cli_version": __version__,
        "python_version": sys.version.split()[0],
        "openssl_version": ssl.OPENSSL_VERSION,
        "tls13_supported": bool(getattr(ssl, "HAS_TLSv1_3", False)),
        "endpoint": client.endpoint,
        "pin_mode": client.pin_mode,
    }
    ok = sys.version_info >= (3, 9)

    if CRED_PATH.exists():
        mode_oct = stat.S_IMODE(os.stat(CRED_PATH).st_mode)
        checks["credentials_file"] = str(CRED_PATH)
        checks["credentials_permissions"] = f"0{mode_oct:o}"
        if os.name != "nt" and (mode_oct & 0o077) != 0:
            checks["credentials_warning"] = "Permissions broader than 0600; run chmod 600 ~/.clawnexus/credentials.json"
    else:
        checks["credentials_file"] = "not_configured (using env vars or anonymous doctor)"

    try:
        t0 = time.time()
        st, hdrs, _ = client.request_raw("GET", "/api/v1/health", require_auth=False, retries=1)
        rtt_ms = round((time.time() - t0) * 1000.0, 1)
        checks["health_http_status"] = st
        checks["rtt_ms"] = rtt_ms
        checks["peer_spki_sha256"] = client.last_peer_spki_sha256
        checks["spki_pin_matched"] = client.last_spki_pin_matched
        if st != 200:
            ok = False
        date_hdr = hdrs.get("date")
        if date_hdr:
            dt = email.utils.parsedate_to_datetime(date_hdr)
            skew_sec = round(abs(time.time() - dt.timestamp()), 2)
            checks["clock_skew_sec"] = skew_sec
            checks["clock_skew_ok"] = skew_sec <= 60.0
            if skew_sec > 60.0:
                ok = False
                checks["clock_warning"] = f"Clock skew {skew_sec}s exceeds ±60s HMAC v2 anti-replay window"
    except Exception as exc:
        ok = False
        checks["connection_error"] = str(exc)

    checks["status"] = "ok" if ok else "failed"
    print(json.dumps(checks, indent=2, ensure_ascii=False))
    return 0 if ok else 4


def _download_artifacts(
    client: ClawNexusClient,
    job_id: str,
    pdf_out: str | None,
    json_out: str | None,
    bundle_out: str | None,
) -> dict:
    downloaded = {}
    st_j, _, raw_j = client.request_raw("GET", f"/api/v1/inspect/jobs/{job_id}/report.json")
    if st_j != 200:
        raise RuntimeError(f"Failed to fetch report.json (HTTP {st_j}): {raw_j.decode('utf-8', errors='replace')}")
    report_obj = json.loads(raw_j.decode("utf-8"))
    if json_out:
        jp = Path(json_out)
        jp.parent.mkdir(parents=True, exist_ok=True)
        jp.write_bytes(raw_j)
        downloaded["report_json"] = str(jp)
    if pdf_out:
        st_p, _, raw_p = client.request_raw("GET", f"/api/v1/inspect/jobs/{job_id}/report.pdf")
        if st_p != 200:
            raise RuntimeError(f"Failed to fetch report.pdf (HTTP {st_p})")
        pp = Path(pdf_out)
        pp.parent.mkdir(parents=True, exist_ok=True)
        pp.write_bytes(raw_p)
        downloaded["report_pdf"] = str(pp)
    if bundle_out:
        st_b, _, raw_b = client.request_raw("GET", f"/api/v1/inspect/jobs/{job_id}/bundle.zip")
        if st_b != 200:
            raise RuntimeError(f"Failed to fetch bundle.zip (HTTP {st_b})")
        bp = Path(bundle_out)
        bp.parent.mkdir(parents=True, exist_ok=True)
        bp.write_bytes(raw_b)
        downloaded["bundle_zip"] = str(bp)
    return {"report": report_obj, "downloaded": downloaded}


def _reclaim_job(client: ClawNexusClient, job_id: str) -> dict:
    payload = json.dumps({"confirm_reclaim": True}).encode("utf-8")
    st, _, raw = client.request_raw(
        "POST",
        f"/api/v1/inspect/jobs/{job_id}/reclaim",
        body=payload,
        content_type="application/json",
    )
    body = json.loads(raw.decode("utf-8", errors="replace"))
    if st != 200:
        raise RuntimeError(f"Failed to reclaim job {job_id} (HTTP {st}): {body}")
    return body.get("reclaim_receipt", body)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="clawprobe",
        description="ClawProbe APK Deep Analysis & 300s Live Dynamic Technical Inspection API Client (v1.3)",
    )
    parser.add_argument("--version", action="version", version=f"clawprobe {__version__}")
    parser.add_argument("--endpoint", default=None, help=f"Gateway URL (default: {DEFAULT_PUBLIC_ENDPOINT})")
    parser.add_argument("--api-key", default=None, help="Commercial API Key (cnx_live_* or env CLAWNEXUS_API_KEY)")
    parser.add_argument("--secret", default=None, help="HMAC-SHA256 Sign Secret (sec_* or env CLAWNEXUS_SIGN_SECRET)")
    parser.add_argument("--ca-cert", default=None, help="Optional custom TLS CA PEM path")
    parser.add_argument("--spki-pin", default=None, help="Optional comma-separated SPKI SHA-256 Base64 pins")
    parser.add_argument("--pin-mode", choices=["ca", "strict", "off"], default=None, help="TLS pin policy (default: ca)")

    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="Check Python/OpenSSL TLS 1.3 support, certificate chain, and ±60s clock skew")

    p_auth = sub.add_parser("auth", help="Manage CLI authentication credentials")
    auth_sub = p_auth.add_subparsers(dest="auth_cmd", required=True)
    p_login = auth_sub.add_parser("login", help="Store APIKEY, HMAC secret, and endpoint in ~/.clawnexus/credentials.json")
    p_login.add_argument("--endpoint", default=DEFAULT_PUBLIC_ENDPOINT, help=f"Service endpoint (default: {DEFAULT_PUBLIC_ENDPOINT})")
    p_login.add_argument("--api-key", required=True)
    p_login.add_argument("--secret", required=True)
    p_login.add_argument("--spki-pin", default=None)
    auth_sub.add_parser("verify", help="Verify TLS 1.3 handshake, HMAC v2 authentication, and inspection credits")

    p_an = sub.add_parser("analyze", help="Submit APK for 300s 3-stage live sandbox technical inspection")
    p_an.add_argument("apk", help="Path to target .apk file")
    p_an.add_argument(
        "--attest-authorized",
        action="store_true",
        default=False,
        help="Mandatory: Attest that you hold lawful ownership or written authorization to submit this APK for technical testing",
    )
    p_an.add_argument("--mode", choices=["privacy", "forensic", "sdk-hunt"], default="privacy")
    p_an.add_argument("--confidential", action="store_true", default=False, help="Enable confidential vault + TTL shred")
    p_an.add_argument("--ttl", type=int, default=72, help="Confidential retention TTL in hours (default 72)")
    p_an.add_argument("--fail-on-preconsent", action="store_true", default=False, help="Exit code 2 if Stage-1 pre-consent flows exist")
    p_an.add_argument("--queue-timeout", type=int, default=900, help="Max seconds to wait in queue if all sandboxes are busy (default 900)")
    p_an.add_argument("--no-wait", action="store_true", default=False, help="Return job_id immediately without polling")
    p_an.add_argument("--out", default=None, help="Output path for PDF Technical Inspection Report")
    p_an.add_argument("--json-out", default=None, help="Output path for JSON Technical Inspection Report")
    p_an.add_argument("--bundle", default=None, help="Output path for full ZIP bundle (PDF+JSON+PCAP+SHA256)")
    p_an.add_argument(
        "--reclaim",
        action="store_true",
        default=False,
        help="Immediately 3-pass overwrite & zero-shred server-side job artifacts after downloading local deliverables",
    )

    p_job = sub.add_parser("job", help="Query inspection job status and download technical report deliverables")
    p_job.add_argument("job_id", help="Job ID (cn_apk_*)")
    p_job.add_argument("--out", default=None, help="Output path for PDF report")
    p_job.add_argument("--json-out", default=None, help="Output path for JSON report")
    p_job.add_argument("--bundle", default=None, help="Output path for ZIP bundle")
    p_job.add_argument("--fail-on-preconsent", action="store_true", default=False)
    p_job.add_argument(
        "--reclaim",
        action="store_true",
        default=False,
        help="Immediately 3-pass overwrite & zero-shred server-side job artifacts after downloading",
    )

    p_rec = sub.add_parser("reclaim", help="Immediately 3-pass overwrite & zero-shred server-side artifacts for a completed job")
    p_rec.add_argument("job_id", help="Job ID (cn_apk_*)")

    p_desk = sub.add_parser(
        "desktop",
        help="Launch the Open-Source Cross-Platform (Windows/macOS) Desktop GUI Reference Workbench Demo",
    )
    p_desk.add_argument("--headless-self-test", action="store_true", help="Run system keychain & snippet generation self-test")

    args = parser.parse_args()

    if args.cmd == "desktop":
        from .desktop import launch_gui, main as desktop_main
        if getattr(args, "headless_self_test", False):
            sys.argv = ["clawprobe-desktop", "--headless-self-test", "--endpoint", args.endpoint or DEFAULT_PUBLIC_ENDPOINT]
            sys.exit(desktop_main())
        launch_gui(initial_endpoint=args.endpoint or DEFAULT_PUBLIC_ENDPOINT)
        return

    if args.cmd == "auth" and args.auth_cmd == "login":
        saved = save_credentials(args.endpoint, args.api_key, args.secret, spki_pin=args.spki_pin)
        print(
            json.dumps(
                {
                    "status": "saved",
                    "credentials_file": str(saved),
                    "endpoint": (args.endpoint or DEFAULT_PUBLIC_ENDPOINT).rstrip("/"),
                    "spki_pinning": "strict" if args.spki_pin else "ca_chain_verified",
                },
                indent=2,
            )
        )
        return

    client = _build_client(args)

    if args.cmd == "doctor":
        sys.exit(_run_doctor(client))

    if args.cmd == "auth" and args.auth_cmd == "verify":
        st, body = client.request_json("GET", "/api/v1/auth/verify")
        print(json.dumps(body, indent=2, ensure_ascii=False))
        sys.exit(0 if st == 200 else 1)

    if args.cmd == "analyze":
        if not args.attest_authorized:
            print(
                json.dumps(
                    {
                        "status": "error",
                        "error_code": "ERR_AUTHORIZATION_ATTESTATION_REQUIRED",
                        "message": "Mandatory flag `--attest-authorized` missing: you must attest lawful ownership or written authorization to submit this APK under ClawNexus Terms of Service.",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            sys.exit(1)

        apk_p = Path(args.apk)
        if not apk_p.exists():
            print(json.dumps({"status": "error", "message": f"APK not found: {apk_p}"}), file=sys.stderr)
            sys.exit(1)

        q_deadline = time.time() + max(0, int(args.queue_timeout))
        q_attempt = 0
        while True:
            try:
                st, sub_resp = client.upload_multipart(
                    "/api/v1/inspect/submit",
                    file_path=apk_p,
                    fields={
                        "mode": args.mode,
                        "confidential": "true" if args.confidential else "false",
                        "ttl_hours": str(args.ttl),
                        "authorization_attested": "true",
                        "wait": "false",
                    },
                )
            except Exception as net_exc:
                print(json.dumps({"status": "error", "error_code": "ERR_NETWORK_UNAVAILABLE", "message": str(net_exc)}), file=sys.stderr)
                sys.exit(4)

            err_code = str(sub_resp.get("error_code") or "")
            if st == 429 and err_code == "ERR_P0_HOT_SPARE_BUSY" and time.time() < q_deadline:
                q_attempt += 1
                wait_s = min(60, 15 * (2 ** min(q_attempt - 1, 2)))
                rem_q = int(max(0.0, q_deadline - time.time()))
                print(
                    f"[clawprobe] All clean sandboxes busy (attempt #{q_attempt}); retrying in {wait_s}s (queue timeout remaining: {rem_q}s)...",
                    file=sys.stderr,
                )
                time.sleep(wait_s)
                continue
            break

        if st != 200:
            print(json.dumps(sub_resp, indent=2, ensure_ascii=False), file=sys.stderr)
            err_code = str(sub_resp.get("error_code") or "")
            if err_code in ("ERR_QUOTA_EXCEEDED", "ERR_PACKAGE_QUOTA_EXCEEDED", "ERR_PACKAGE_NOT_IN_WHITELIST"):
                sys.exit(3)
            if st in (429, 502, 503, 504):
                sys.exit(4)
            sys.exit(1)

        job_id = sub_resp["job_id"]
        if args.no_wait:
            print(json.dumps(sub_resp, indent=2, ensure_ascii=False))
            return

        deadline = time.time() + 420.0
        st_body: dict = {}
        while time.time() < deadline:
            time.sleep(2.5)
            _, st_body = client.request_json("GET", f"/api/v1/inspect/jobs/{job_id}")
            jst = st_body.get("job_status", "")
            if jst == "COMPLETED":
                break
            if jst == "FAILED":
                print(json.dumps(st_body, indent=2, ensure_ascii=False), file=sys.stderr)
                sys.exit(1)
        else:
            print(json.dumps({"status": "error", "error_code": "ERR_INSPECT_TIMEOUT", "message": "Timed out waiting for inspection completion", "job_id": job_id}), file=sys.stderr)
            sys.exit(4)

        dl = _download_artifacts(client, job_id, args.out, args.json_out, args.bundle)
        reclaim_receipt = _reclaim_job(client, job_id) if args.reclaim else None
        rep = dl["report"]
        summary = rep.get("layer1_deterministic_network_ledger", {}).get("summary", {})
        pre_detected = bool(summary.get("pre_consent_network_detected"))
        out_payload = {
            "status": "ok",
            "report_title": rep.get("report_title"),
            "job_id": job_id,
            "package_name": rep.get("layer1_deterministic_network_ledger", {}).get("package_name"),
            "wall_time_sec": st_body.get("wall_time_sec"),
            "authorization_attestation": rep.get("report_metadata", {}).get("customer_authorization_attestation"),
            "summary": summary,
            "anchored_findings": rep.get("anchored_technical_synthesis", {}).get("verified_anchored_findings", []),
            "downloaded_files": dl["downloaded"],
        }
        if reclaim_receipt is not None:
            out_payload["reclaim_receipt"] = reclaim_receipt
        print(json.dumps(out_payload, indent=2, ensure_ascii=False))
        if args.fail_on_preconsent and pre_detected:
            sys.exit(2)
        return

    if args.cmd == "reclaim":
        receipt = _reclaim_job(client, args.job_id)
        print(json.dumps({"status": "ok", "reclaim_receipt": receipt}, indent=2, ensure_ascii=False))
        return

    if args.cmd == "job":
        st, st_body = client.request_json("GET", f"/api/v1/inspect/jobs/{args.job_id}")
        if st != 200:
            print(json.dumps(st_body, indent=2, ensure_ascii=False), file=sys.stderr)
            sys.exit(1)
        if st_body.get("job_status") != "COMPLETED" or not (args.out or args.json_out or args.bundle or args.reclaim):
            print(json.dumps(st_body, indent=2, ensure_ascii=False))
            return
        dl = _download_artifacts(client, args.job_id, args.out, args.json_out, args.bundle) if (args.out or args.json_out or args.bundle) else {"report": {}, "downloaded": {}}
        reclaim_receipt = _reclaim_job(client, args.job_id) if args.reclaim else None
        rep = dl["report"]
        summary = rep.get("layer1_deterministic_network_ledger", {}).get("summary", {})
        res_out = {**st_body, "summary": summary, "downloaded_files": dl["downloaded"]}
        if reclaim_receipt is not None:
            res_out["reclaim_receipt"] = reclaim_receipt
            res_out["job_status"] = "RECLAIMED_SHREDDED"
        print(json.dumps(res_out, indent=2, ensure_ascii=False))
        if args.fail_on_preconsent and summary.get("pre_consent_network_detected"):
            sys.exit(2)


if __name__ == "__main__":
    main()
