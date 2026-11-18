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
        forbidden_window_hashes = {
            4: frozenset([
                "f9a75ecb0e5e127ed6917a563840dd2a33d661d385f9808f0547d188883a01d1",
                "0f8eb4b72b6e0c9e88b388eb967b49e067ef1004bf07bffc22c3acb13b43580a",
                "67f2d22514622d1be30c14ee9f3cb104503a159a33a656ca91a1953aa9616429",
                "1ab8b7f3160763c3ad6563287ef02a6022703117f43a94130f84c2e7ed3d367f",
            ]),
            5: frozenset([
                "9d20b602fbe5b565409aa4e64553bf531d75dd30ba9d0fdc2440ddc07e16999f",
                "064c28496762af7592c2d84e7acd32e95c8fdb2e09602e50a217b449201272d8",
                "c392fb854c31498c87f44406813903470382477010f878554ee4a4edc8cc524f",
                "02dae179e16841345a4e5cb7996e022ea6f45aeb4cbfa4811a76934328c2d24e",
            ]),
            6: frozenset([
                "c7496688a99973b04fee89173591f09cd1d650bd9def3a3a47ae36edbd277522",
                "2cb5049d289d9b03fbe6383613d680969fef82c092e583e80c258b3eb7024399",
                "c9e0a40ab5458b21622c05c24068a1bcd94642f86814729b9f3796590abfcc55",
            ]),
            7: frozenset([
                "a35906a5b5e2d3b78bd2513a9fbb4965726f949cd6220648984deb8bd86fda62",
                "6dbe9d04efa48bf698d72c1df6829e3c7837219a7869a35f91cc74c5b195052b",
                "538dcececb7751af5f51e2203591efc1d48cc586bbd9c991bb67c5b99fbc863b",
                "badc57e9a107c1e794a910fabdc6b80b22897525ef735cedf15748e0cef975d7",
            ]),
            8: frozenset([
                "89717ddba1be520eed9b14a8bacfa507b79608b04b7e1b1360a18183cdab4c1d",
                "faa8690ae801ec25cc668357e6e1e441916e7b4df54abd236f33b219f65316a8",
                "f31006e706fcc58856f733c46fbe7c9618908e7ae476fa3fe47ab58413503957",
                "c7ecb245374fc418d6290e8a67dad19032efd73f8f9a77b9ddacfa24b1d4b7af",
                "ac8cc19bba56cb1b39e99cb78ef1ddd38ea7b6e22a7996c9d06538dc2bb98650",
                "cfe01afd94ec594ce78ee7450f526145d1f83f5d798081b0ab9d1f5a8f93097e",
            ]),
            10: frozenset([
                "071366614492cac29cf0a56532f028a52942ee837b0394e1345efe11bec563ff",
                "90af2fc6d00f38600e023fc3cce599d6724edc949201dd07912231ddfa6c3540",
            ]),
            11: frozenset([
                "9a139a5d99d45485d6eb802214d7d748d99325092f82da93f0afdc8a4ca0901c",
            ]),
            12: frozenset([
                "c309821f889a0a17198e1ea6abc37846434581fe28523f43806191ffe88e96fd",
            ]),
            16: frozenset([
                "667ecbd06bb0e06021f89ecf77222cadb715fdc8835abdb02d9b20dec8fc3af9",
                "d503ca33bbd2114fcb130424e398afa3d81a37c89dfc08480333cd8230b5aa4b",
            ]),
        }
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
            n_chars = len(content)
            for win_len, target_hashes in forbidden_window_hashes.items():
                if n_chars < win_len:
                    continue
                unique_windows = {
                    content[i : i + win_len]
                    for i in range(n_chars - win_len + 1)
                    if ("0" <= content[i] <= "9") or ("a" <= content[i] <= "z")
                }
                for sub in unique_windows:
                    if not sub.isascii():
                        continue
                    digest = hashlib.sha256(sub.encode("utf-8")).hexdigest()
                    self.assertNotIn(
                        digest,
                        target_hashes,
                        f"Forbidden internal token hash {digest[:12]}... matched in {path}",
                    )


if __name__ == "__main__":
    unittest.main()
