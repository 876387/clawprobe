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
import urllib.parse
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent.parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

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


def _extract_flow_domain_stdlib(flow: dict) -> str:
    for k in ("effective_domain", "tls_sni", "http_host", "dns_resolved_domain", "resolved_domain"):
        val = str(flow.get(k) or "").strip().lower()
        if val:
            return val
    rip = str(flow.get("remote_ip") or "").strip()
    rport = flow.get("remote_port")
    if rip and rport:
        return f"{rip}:{rport}"
    return rip or "unknown_endpoint"


def _extract_stage1_flows_stdlib(report: dict) -> list[dict]:
    l1 = report.get("layer1_deterministic_network_ledger") or {}
    flows = l1.get("flows") or []
    anchors = set(l1.get("pre_consent_flow_anchors") or [])
    stage1_flows = []
    for f in flows:
        stages = f.get("stages_active") or []
        is_s1 = (
            bool(f.get("pre_consent_flow"))
            or int(f.get("stage_first_seen") or 0) == 1
            or (1 in stages)
            or (str(f.get("flow_id") or "") in anchors)
        )
        if is_s1:
            stage1_flows.append(f)
    return stage1_flows


def _compare_inspection_reports_stdlib(
    before_report: dict,
    after_report: dict,
    delegating_org: str = "",
    service_partner_name: str = "",
) -> dict:
    b_l1 = before_report.get("layer1_deterministic_network_ledger") or {}
    a_l1 = after_report.get("layer1_deterministic_network_ledger") or {}
    b_s1_flows = _extract_stage1_flows_stdlib(before_report)
    a_s1_flows = _extract_stage1_flows_stdlib(after_report)

    b_s1_count = int((b_l1.get("summary") or {}).get("pre_consent_flow_count", len(b_s1_flows)))
    if len(b_s1_flows) != b_s1_count and b_s1_flows:
        b_s1_count = len(b_s1_flows)
    a_s1_count = int((a_l1.get("summary") or {}).get("pre_consent_flow_count", len(a_s1_flows)))
    if len(a_s1_flows) != a_s1_count and (a_s1_flows or a_s1_count == 0):
        a_s1_count = len(a_s1_flows)

    b_s1_domains = sorted({_extract_flow_domain_stdlib(f) for f in b_s1_flows if _extract_flow_domain_stdlib(f)})
    a_s1_domains = sorted({_extract_flow_domain_stdlib(f) for f in a_s1_flows if _extract_flow_domain_stdlib(f)})
    b_s1_set = set(b_s1_domains)
    a_s1_set = set(a_s1_domains)
    eliminated_stage1 = sorted(b_s1_set - a_s1_set)
    remaining_stage1 = sorted(b_s1_set & a_s1_set)
    regressed_stage1 = sorted(a_s1_set - b_s1_set)

    reduction_count = max(0, b_s1_count - a_s1_count)
    reduction_pct = round(((b_s1_count - a_s1_count) / float(b_s1_count)) * 100.0, 1) if b_s1_count > 0 else (100.0 if a_s1_count == 0 else -100.0)
    if a_s1_count == 0:
        s1_status = "STAGE1_CLEARED"
        s1_human_summary = "本次检测条件下（约300秒三阶段动态运行）未观测到同意前联网"
    elif a_s1_count > b_s1_count or regressed_stage1:
        s1_status = "REGRESSED"
        s1_human_summary = f"本次检测条件下阶段1观测到 {a_s1_count} 条外联流（较整改前增加或出现新域名）"
    elif a_s1_count < b_s1_count or eliminated_stage1:
        s1_status = "PARTIAL_IMPROVED"
        s1_human_summary = f"本次检测条件下阶段1外联流由 {b_s1_count} 条减少至 {a_s1_count} 条（部分消减）"
    else:
        s1_status = "UNCHANGED"
        s1_human_summary = f"本次检测条件下阶段1外联流保持 {a_s1_count} 条（无明显变化）"

    def _sdk_stage_map(rep: dict) -> dict[str, set[int]]:
        flows = (rep.get("layer1_deterministic_network_ledger") or {}).get("flows") or []
        out: dict[str, set[int]] = {}
        for f in flows:
            sdk = str(f.get("matched_sdk") or "").strip()
            if not sdk or sdk == "Host/Unclassified":
                continue
            stages = {int(s) for s in (f.get("stages_active") or []) if int(s) in (1, 2, 3)}
            if f.get("pre_consent_flow") or int(f.get("stage_first_seen") or 0) == 1:
                stages.add(1)
            elif not stages:
                stages.add(int(f.get("stage_first_seen") or 2))
            out.setdefault(sdk, set()).update(stages)
        return out

    b_sdk = _sdk_stage_map(before_report)
    a_sdk = _sdk_stage_map(after_report)
    deferred_sdks = sorted(
        sdk for sdk in set(b_sdk) | set(a_sdk)
        if 1 in b_sdk.get(sdk, set()) and 1 not in a_sdk.get(sdk, set())
    )

    return {
        "report_title": "移动应用网络通联与隐私合规整改前后对比技术分析单（自查参考）",
        "delegating_org": str(delegating_org or ""),
        "service_partner_name": str(service_partner_name or ""),
        "stage1_preconsent_diff": {
            "before_preconsent_flow_count": b_s1_count,
            "after_preconsent_flow_count": a_s1_count,
            "flow_count_delta": a_s1_count - b_s1_count,
            "delta_flow_count": a_s1_count - b_s1_count,
            "reduction_count": reduction_count,
            "reduction_pct": reduction_pct,
            "before_stage1_domains": b_s1_domains,
            "after_stage1_domains": a_s1_domains,
            "eliminated_stage1_domains": eliminated_stage1,
            "remaining_stage1_domains": remaining_stage1,
            "regressed_stage1_domains": regressed_stage1,
            "status_tag": s1_status,
            "status_human_summary": s1_human_summary,
        },
        "sdk_stage_migration_diff": {
            "before_stage1_sdks": sorted(k for k, v in b_sdk.items() if 1 in v),
            "after_stage1_sdks": sorted(k for k, v in a_sdk.items() if 1 in v),
            "deferred_to_post_consent_sdks": deferred_sdks,
        },
        "roi_closer_card": {
            "annual_plan_price_yuan": 2699.0,
            "annual_plan_quota": 300,
            "annual_plan_unit_cost_yuan": 8.99,
            "monthly_plan_yuan": 299.0,
            "monthly_plan_quota": 25,
            "monthly_plan_unit_cost_yuan": 11.96,
        },
    }


def _write_minimal_pdf_stdlib(diff_report: dict, output_pdf_path: Path) -> dict:
    output_pdf_path.parent.mkdir(parents=True, exist_ok=True)
    s1 = diff_report.get("stage1_preconsent_diff") or {}
    summary_line = (
        f"ClawProbe Diff Summary | status={s1.get('status_tag')} | "
        f"before={s1.get('before_preconsent_flow_count')} -> after={s1.get('after_preconsent_flow_count')}"
    )
    stream_bytes = f"BT /F1 11 Tf 48 760 Td ({summary_line}) Tj ET".encode("ascii", errors="replace")
    pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n"
        b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n"
        b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>endobj\n"
        + f"4 0 obj<< /Length {len(stream_bytes)} >>stream\n".encode("ascii")
        + stream_bytes
        + b"\nendstream\nendobj\n"
        b"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n"
        b"xref\n0 6\n0000000000 65535 f \n"
        b"trailer<< /Size 6 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n"
    )
    output_pdf_path.write_bytes(pdf_bytes)
    return {"pdf_path": str(output_pdf_path), "pdf_size_bytes": len(pdf_bytes)}


def main(argv: list[str] | None = None) -> int:
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
    p_an.add_argument("--out", default=None, help="Output path for PDF Technical Analysis Report")
    p_an.add_argument("--json-out", default=None, help="Output path for JSON Technical Analysis Report")
    p_an.add_argument("--bundle", default=None, help="Output path for full ZIP bundle (PDF+JSON+PCAP+SHA256)")
    p_an.add_argument("--delegating-org", default="", help="Optional delegating organization name (委托自查单位名称, max 64 chars)")
    p_an.add_argument("--service-partner", default="", help="Optional technical service partner name (技术服务协作方/代办机构名称, max 64 chars)")
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

    p_sub = sub.add_parser(
        "subclients",
        help="List agency multi-subclient inspection report ledger grouped by delegating organization (`delegating_org`) and tenant quota summary",
    )
    p_sub.add_argument("--org", default="", help="Optional filter by delegating organization name (委托自查单位名称)")
    p_sub.add_argument("--limit", type=int, default=50, help="Maximum recent jobs to inspect (1..200, default 50)")
    p_sub.add_argument("--json", action="store_true", default=False, help="Print raw JSON ledger output")

    p_diff = sub.add_parser(
        "diff",
        help="Generate Before-vs-After Remediation Diff Technical Analysis Report (supports offline local JSON paths or online job IDs)",
    )
    p_diff.add_argument("--before", required=True, help="Path to before report.json OR remote job_id (cn_apk_*)")
    p_diff.add_argument("--after", required=True, help="Path to after report.json OR remote job_id (cn_apk_*)")
    p_diff.add_argument("--delegating-org", default="", help="Optional delegating organization name (委托自查单位名称)")
    p_diff.add_argument("--service-partner", default="", help="Optional service partner / agency name (技术服务协作方名称)")
    p_diff.add_argument("--out", default=None, help="Output path for Remediation Diff PDF report")
    p_diff.add_argument("--json-out", default=None, help="Output path for Remediation Diff JSON report")

    p_desk = sub.add_parser(
        "desktop",
        help="Launch the Open-Source Cross-Platform (Windows/macOS) Desktop GUI Reference Workbench Demo",
    )
    p_desk.add_argument("--import-sub", default="", help="Import a cp_sub_v1_... subscription token into OS Keychain")
    p_desk.add_argument("--status", action="store_true", help="Print current desktop credential & OS keychain status as JSON")
    p_desk.add_argument("--headless-self-test", action="store_true", help="Run system keychain & snippet generation self-test")

    args = parser.parse_args(argv)

    if args.cmd == "diff":
        b_raw = str(args.before or "").strip()
        a_raw = str(args.after or "").strip()
        if b_raw.startswith("cn_apk_") and a_raw.startswith("cn_apk_"):
            import base64

            client = _build_client(args)
            st, body = client.request_json(
                "POST",
                "/api/v1/inspect/diff",
                payload={
                    "before_job_id": b_raw,
                    "after_job_id": a_raw,
                    "delegating_org": getattr(args, "delegating_org", ""),
                    "service_partner_name": getattr(args, "service_partner", ""),
                    "render_pdf": bool(args.out),
                },
            )
            if st != 200:
                print(json.dumps(body, indent=2, ensure_ascii=False), file=sys.stderr)
                sys.exit(1)
            pdf_art = dict(body.get("pdf_artifact") or {})
            pdf_b64 = pdf_art.pop("pdf_base64", None)
            if args.out and pdf_b64:
                out_p = Path(args.out)
                out_p.parent.mkdir(parents=True, exist_ok=True)
                out_p.write_bytes(base64.b64decode(pdf_b64))
                pdf_art["pdf_out"] = str(out_p)
                body["pdf_out"] = str(out_p)
            if body.get("pdf_artifact") is not None:
                body["pdf_artifact"] = pdf_art
            if args.json_out and body.get("diff_report"):
                jp = Path(args.json_out)
                jp.parent.mkdir(parents=True, exist_ok=True)
                jp.write_text(json.dumps(body["diff_report"], indent=2, ensure_ascii=False), encoding="utf-8")
                body["json_out"] = str(jp)
            print(json.dumps(body, indent=2, ensure_ascii=False))
            return 0

        b_path = Path(b_raw)
        a_path = Path(a_raw)
        if not b_path.is_file() or not a_path.is_file():
            print(
                json.dumps(
                    {
                        "status": "error",
                        "error_code": "ERR_DIFF_INPUT_NOT_FOUND",
                        "message": f"Local diff report JSON file not found: before={b_raw}, after={a_raw}",
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
                file=sys.stderr,
            )
            sys.exit(1)

        b_rep = json.loads(b_path.read_text(encoding="utf-8"))
        a_rep = json.loads(a_path.read_text(encoding="utf-8"))
        eng_mod = next(
            (
                m
                for k, m in list(sys.modules.items())
                if k.endswith("diff_report_engine") and hasattr(m, "compare_inspection_reports")
            ),
            None,
        )
        if eng_mod is not None:
            diff_obj = eng_mod.compare_inspection_reports(
                before_report=b_rep,
                after_report=a_rep,
                delegating_org=getattr(args, "delegating_org", ""),
                service_partner_name=getattr(args, "service_partner", ""),
            )
            pdf_info = eng_mod.render_remediation_diff_pdf(diff_obj, Path(args.out)) if args.out else None
        else:
            diff_obj = _compare_inspection_reports_stdlib(
                before_report=b_rep,
                after_report=a_rep,
                delegating_org=getattr(args, "delegating_org", ""),
                service_partner_name=getattr(args, "service_partner", ""),
            )
            pdf_info = _write_minimal_pdf_stdlib(diff_obj, Path(args.out)) if args.out else None
        if args.json_out:
            jp = Path(args.json_out)
            jp.parent.mkdir(parents=True, exist_ok=True)
            jp.write_text(json.dumps(diff_obj, indent=2, ensure_ascii=False), encoding="utf-8")
        print(
            json.dumps(
                {
                    "status": "ok",
                    "mode": "offline_local_diff",
                    "report_title": diff_obj["report_title"],
                    "human_summary": diff_obj["stage1_preconsent_diff"].get("status_human_summary", ""),
                    "stage1_preconsent_diff": diff_obj["stage1_preconsent_diff"],
                    "sdk_stage_migration_diff": {
                        "deferred_to_post_consent_sdks": diff_obj["sdk_stage_migration_diff"]["deferred_to_post_consent_sdks"],
                    },
                    "roi_closer_card": diff_obj["roi_closer_card"],
                    "json_out": str(args.json_out) if args.json_out else None,
                    "pdf_out": pdf_info["pdf_path"] if pdf_info else None,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    if args.cmd == "desktop":
        from .desktop import launch_gui, main as desktop_main
        desk_argv = ["clawprobe-desktop", "--endpoint", args.endpoint or DEFAULT_PUBLIC_ENDPOINT]
        if getattr(args, "import_sub", ""):
            sys.argv = desk_argv + ["--import-sub", args.import_sub]
            sys.exit(desktop_main())
        if getattr(args, "status", False):
            sys.argv = desk_argv + ["--status"]
            sys.exit(desktop_main())
        if getattr(args, "headless_self_test", False):
            sys.argv = desk_argv + ["--headless-self-test"]
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
        sub_fields: dict[str, str] = {
            "mode": args.mode,
            "confidential": "true" if args.confidential else "false",
            "ttl_hours": str(args.ttl),
            "authorization_attested": "true",
            "wait": "false",
        }
        if getattr(args, "delegating_org", ""):
            sub_fields["delegating_org"] = str(args.delegating_org).strip()[:64]
        if getattr(args, "service_partner", ""):
            sub_fields["service_partner_name"] = str(args.service_partner).strip()[:64]
        while True:
            try:
                st, sub_resp = client.upload_multipart(
                    "/api/v1/inspect/submit",
                    file_path=apk_p,
                    fields=sub_fields,
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
        if sub_resp.get("instant_dedup"):
            print(
                f"[clawprobe] ⚡ SHA-256 instant upload (0-byte deduplication) hit for job {job_id}!",
                file=sys.stderr,
            )
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
            "instant_dedup": bool(sub_resp.get("instant_dedup")),
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

    if args.cmd == "subclients":
        q_params: dict[str, str] = {"limit": str(max(1, min(int(args.limit or 50), 200)))}
        if getattr(args, "org", "") and str(args.org).strip():
            q_params["delegating_org"] = str(args.org).strip()
        qs = urllib.parse.urlencode(q_params)
        st, body = client.request_json("GET", f"/api/v1/inspect/subclients?{qs}")
        if st != 200:
            print(json.dumps(body, indent=2, ensure_ascii=False), file=sys.stderr)
            sys.exit(1)
        if getattr(args, "json", False):
            print(json.dumps(body, indent=2, ensure_ascii=False))
            return
        qs_info = body.get("quota_summary") or {}
        print(
            f"=== ClawProbe Agency Multi-Subclient Ledger | Tenant: {body.get('tenant_name') or body.get('tenant_id')} ({qs_info.get('tier')}) ==="
        )
        print(
            f"Credits Remaining: {qs_info.get('total_inspect_credits_remaining')} | "
            f"Today Used: {qs_info.get('today_inspect_used')}/{qs_info.get('daily_inspect_quota')} | "
            f"Bound Packages: {qs_info.get('bound_packages_count')}/{qs_info.get('max_unique_packages')} | "
            f"Expires UTC: {qs_info.get('expires_at_utc') or 'N/A'}"
        )
        for grp in body.get("subclient_groups") or []:
            print(
                f"\n[委托单位: {grp.get('delegating_org')}] "
                f"(Total Jobs: {grp.get('total_jobs')}, Completed: {grp.get('completed_jobs')})"
            )
            for jb in grp.get("jobs") or []:
                print(
                    f"  - {jb.get('job_id')} | {jb.get('package_name')} ({jb.get('apk_filename')}) | "
                    f"status={jb.get('status')} | pdf={jb.get('report_pdf_endpoint')}"
                )
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
