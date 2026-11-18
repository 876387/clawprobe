import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from clawprobe import __version__
from clawprobe.client import (
    ClawNexusClient,
    DEFAULT_PINNED_SPKI_SHA256,
    DEFAULT_PUBLIC_ENDPOINT,
    EMBEDDED_PUBLIC_CA_CHAIN_PEM,
    canonicalize_path_and_query,
    compute_hmac_signature_v2,
)


class TestClawProbeOffline(unittest.TestCase):
    def test_version_and_defaults(self):
        self.assertEqual(__version__, "1.3.5")
        self.assertEqual(DEFAULT_PUBLIC_ENDPOINT, "https://www.atooli.com")
        self.assertGreaterEqual(len(DEFAULT_PINNED_SPKI_SHA256), 3)
        self.assertIn("BEGIN CERTIFICATE", EMBEDDED_PUBLIC_CA_CHAIN_PEM)

    def test_hmac_canonical_signing(self):
        canon = canonicalize_path_and_query("/api/v1/quota?b=2&a=1")
        self.assertEqual(canon, "/api/v1/quota?a=1&b=2")
        sig = compute_hmac_signature_v2(
            sign_secret="sec_demo_secret_0001",
            method="GET",
            path_with_query="/api/v1/quota?b=2&a=1",
            timestamp="1700000000",
            nonce="00112233445566778899aabb",
            full_raw_body_sha256=hashlib.sha256(b"").hexdigest(),
        )
        self.assertEqual(len(sig), 64)

    def test_default_ca_pin_mode_vs_strict_pin_mode(self):
        default_client = ClawNexusClient(
            endpoint="https://www.atooli.com",
            api_key="cnx_live_demo0001",
            sign_secret="sec_demo_secret_0001",
        )
        self.assertEqual(default_client.pin_mode, "strict")

        custom_pin = "h3mQK/w8dMmMne2+T0gN9L5DAL5BrhfskqFXjK5oOSo="
        strict_client = ClawNexusClient(
            endpoint="https://www.atooli.com",
            api_key="cnx_live_demo0001",
            sign_secret="sec_demo_secret_0001",
            spki_pins=[custom_pin],
        )
        self.assertEqual(strict_client.pin_mode, "strict")
        self.assertEqual(strict_client.spki_pins, (custom_pin,))

    def test_missing_credentials_raises_value_error(self):
        client = ClawNexusClient(
            endpoint="https://www.atooli.com",
            api_key="",
            sign_secret="",
        )
        with self.assertRaises(ValueError):
            client.request_raw("GET", "/api/v1/quota", b"", require_auth=True)

    def test_cli_version_flag(self):
        proc = subprocess.run(
            [sys.executable, "-m", "clawprobe", "--version"],
            cwd=str(SRC_DIR),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("clawprobe 1.3.5", proc.stdout)

    def test_desktop_demo_headless_self_test(self):
        proc = subprocess.run(
            [sys.executable, "-m", "clawprobe", "desktop", "--headless-self-test"],
            cwd=str(SRC_DIR),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn('"status": "ok"', proc.stdout)
        self.assertIn('"keychain_roundtrip_verified": true', proc.stdout)

        proc_status = subprocess.run(
            [sys.executable, "-m", "clawprobe", "desktop", "--status"],
            cwd=str(SRC_DIR),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn('"status":', proc_status.stdout)

        proc_script = subprocess.run(
            [sys.executable, str(ROOT_DIR / "desktop_client" / "clawprobe_desktop.py"), "--headless-self-test"],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn('"status": "ok"', proc_script.stdout)

    def test_standalone_offline_diff_cli(self):
        before_doc = {
            "layer1_deterministic_network_ledger": {
                "summary": {"pre_consent_flow_count": 2},
                "pre_consent_flow_anchors": ["FL-1", "FL-2"],
                "flows": [
                    {
                        "flow_id": "FL-1",
                        "pre_consent_flow": True,
                        "stage_first_seen": 1,
                        "stages_active": [1, 2],
                        "effective_domain": "cnlogs.umeng.com",
                        "matched_sdk": "SDK::Umeng_Analytics (友盟+统计)",
                    },
                    {
                        "flow_id": "FL-2",
                        "pre_consent_flow": True,
                        "stage_first_seen": 1,
                        "stages_active": [1],
                        "effective_domain": "stats.jpush.cn",
                        "matched_sdk": "SDK::JPush_Aurora (极光推送)",
                    },
                ],
            }
        }
        after_doc = {
            "layer1_deterministic_network_ledger": {
                "summary": {"pre_consent_flow_count": 0},
                "pre_consent_flow_anchors": [],
                "flows": [
                    {
                        "flow_id": "FL-1",
                        "pre_consent_flow": False,
                        "stage_first_seen": 2,
                        "stages_active": [2],
                        "effective_domain": "cnlogs.umeng.com",
                        "matched_sdk": "SDK::Umeng_Analytics (友盟+统计)",
                    }
                ],
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            b_file = tmp_path / "before.json"
            a_file = tmp_path / "after.json"
            out_pdf = tmp_path / "diff.pdf"
            out_json = tmp_path / "diff.json"
            b_file.write_text(json.dumps(before_doc, ensure_ascii=False), encoding="utf-8")
            a_file.write_text(json.dumps(after_doc, ensure_ascii=False), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "clawprobe",
                    "diff",
                    "--before",
                    str(b_file),
                    "--after",
                    str(a_file),
                    "--out",
                    str(out_pdf),
                    "--json-out",
                    str(out_json),
                ],
                cwd=str(tmp_path),
                env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(SRC_DIR)},
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertIn("STAGE1_CLEARED", proc.stdout)
            self.assertTrue(out_pdf.exists())
            self.assertTrue(out_json.exists())
            parsed = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(parsed["stage1_preconsent_diff"]["status_tag"], "STAGE1_CLEARED")
            self.assertIn(
                "SDK::Umeng_Analytics (友盟+统计)",
                parsed["sdk_stage_migration_diff"]["deferred_to_post_consent_sdks"],
            )

    def test_zero_internal_ip_or_secret_leakage(self):
        forbidden_tokens = [
            "192.168.",
            "122.224.",
            "218.75.",
            "112.124.",
            "172.30.",
            "4060",
            "5000",
            "gateway_",
            "clawinsight",
            "arm11",
            "cn_arm",
            "node11",
            "node_agent",
            "pool_manager",
            "nftables",
            "xt_nflog",
            "nflog",
            "skuid",
            "tmpfs",
            "clawbox",
            "fs-net",
            "byteetbert",
            "qwen",
            "redroid",
            "tnt_",
            "key_357a4b95c6c2",
            "key_c8168c27c517",
        ]
        scan_targets = (
            list(SRC_DIR.rglob("*.py"))
            + list((ROOT_DIR / "desktop_client").rglob("*.py"))
            + list((ROOT_DIR / "desktop_client").rglob("*.md"))
            + list((ROOT_DIR / "samples").rglob("*.json"))
            + [
                ROOT_DIR / "README.md",
                ROOT_DIR / "SECURITY.md",
                ROOT_DIR / "CONTRIBUTING.md",
                ROOT_DIR / "CHANGELOG.md",
                ROOT_DIR / "pyproject.toml",
            ]
        )
        for path in scan_targets:
            if not path.exists():
                continue
            content = path.read_text(encoding="utf-8").lower()
            for token in forbidden_tokens:
                self.assertNotIn(
                    token.lower(),
                    content,
                    f"Forbidden internal token {token!r} found in {path}",
                )


if __name__ == "__main__":
    unittest.main()
