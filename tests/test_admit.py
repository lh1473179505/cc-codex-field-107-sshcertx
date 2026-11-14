from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sshcertx.engine import admit_object, inspect_object  # noqa: E402
from sshcertx.load import load_json  # noqa: E402

NOW = 1781784000  # 2026-06-18T12:00:00Z

EXPECTED = {
    "ok-login": ("allow", []),
    "ok-forced": ("allow", []),
    "bad-sig": ("deny", ["bad_signature"]),
    "principal": ("deny", ["principal_denied"]),
    "force-cmd": ("deny", ["force_command_denied"]),
    "source": ("deny", ["source_denied"]),
    "revoked": ("deny", ["ca_revoked"]),
    "replay": ("deny", ["serial_replay"]),
    "expired": ("deny", ["expired"]),
    "early": ("deny", ["not_yet_valid"]),
}

# The replay case reuses a serial already present in fixtures/store-used.json.
USED_STORE = {"items": {"used-1": {"ts": 1}}}


class AdmitFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = load_json(ROOT / "fixtures/keys.json")
        self.policy = load_json(ROOT / "fixtures/policy.json")

    def _store_for(self, case: str):
        return copy.deepcopy(USED_STORE) if case == "replay" else {"items": {}}

    def _admit(self, case: str, obj=None, store=None):
        if obj is None:
            obj = load_json(ROOT / f"fixtures/cases/{case}/input.json")
        return admit_object(
            copy.deepcopy(obj),
            copy.deepcopy(self.keys),
            copy.deepcopy(self.policy),
            store if store is not None else self._store_for(case),
            NOW,
        )

    def test_every_fixture_matches_documented_gate(self) -> None:
        for case, (decision, codes) in EXPECTED.items():
            with self.subTest(case=case):
                report = self._admit(case)
                self.assertEqual(report["decision"], decision)
                self.assertEqual(report["reason_codes"], codes)

    def test_report_shape(self) -> None:
        report = self._admit("ok-login")
        self.assertEqual(set(report), {"decision", "reason_codes", "kind", "notes"})
        self.assertEqual(report["kind"], "sshcertx")
        self.assertEqual(report["reason_codes"], [])

    def test_deny_never_mutates_store_and_allow_records_serial(self) -> None:
        store = {"items": {}}
        report = self._admit("bad-sig", store=store)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(store, {"items": {}})

        report = self._admit("ok-login", store=store)
        self.assertEqual(report["decision"], "allow")
        self.assertIn("ok-0", store["items"])
        replay = self._admit("ok-login", store=store)
        self.assertEqual(replay["reason_codes"], ["serial_replay"])

    def test_tampered_body_fails_signature(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-login/input.json")
        obj["principals"] = ["root", "ops"]
        report = self._admit("ok-login", obj=obj)
        self.assertEqual(report["decision"], "deny")
        self.assertIn("bad_signature", report["reason_codes"])

    def test_revoked_kid_denies_even_with_valid_hmac(self) -> None:
        report = self._admit("revoked")
        self.assertEqual(report["reason_codes"], ["ca_revoked"])

    def test_inspect_output_unchanged(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-login/input.json")
        summary = inspect_object(obj)
        self.assertEqual(set(summary), {"kind", "keys", "preview"})
        self.assertEqual(summary["kind"], "sshcertx")


class CliParityTests(unittest.TestCase):
    def _run_cli(self, case: str, tmp: Path):
        report_path = tmp / f"{case}-report.json"
        store_path = tmp / f"{case}-store.json"
        if case == "replay":
            store_path.write_text(json.dumps(USED_STORE), encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable, "-m", "sshcertx", "admit",
                "--input", str(ROOT / f"fixtures/cases/{case}/input.json"),
                "--keys", str(ROOT / "fixtures/keys.json"),
                "--policy", str(ROOT / "fixtures/policy.json"),
                "--store", str(store_path),
                "--now", "2026-06-18T12:00:00Z",
                "--report", str(report_path),
            ],
            cwd=ROOT, capture_output=True, text=True,
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        store_exists = store_path.exists()
        store = load_json(store_path) if store_exists else None
        return proc.returncode, report, store

    def test_cli_matches_library_for_every_fixture(self) -> None:
        keys = load_json(ROOT / "fixtures/keys.json")
        policy = load_json(ROOT / "fixtures/policy.json")
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            for case, (decision, codes) in EXPECTED.items():
                with self.subTest(case=case):
                    obj = load_json(ROOT / f"fixtures/cases/{case}/input.json")
                    lib = admit_object(
                        copy.deepcopy(obj), copy.deepcopy(keys),
                        copy.deepcopy(policy),
                        copy.deepcopy(USED_STORE) if case == "replay" else {"items": {}},
                        NOW,
                    )
                    rc, cli_report, store = self._run_cli(case, tmp)
                    self.assertEqual(cli_report["decision"], lib["decision"])
                    self.assertEqual(cli_report["reason_codes"], lib["reason_codes"])
                    self.assertEqual(cli_report["decision"], decision)
                    self.assertEqual(cli_report["reason_codes"], codes)
                    if decision == "allow":
                        self.assertEqual(rc, 0)
                        self.assertIsNotNone(store)
                        self.assertIn(obj.get("id"), store["items"])
                    else:
                        self.assertEqual(rc, 1)
                        if case == "replay":
                            self.assertEqual(store, USED_STORE)
                        else:
                            self.assertIsNone(store)


class LoadFailureTests(unittest.TestCase):
    def test_load_failure_exits_2_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            bad_input = tmp / "bad.json"
            bad_input.write_text("{not json", encoding="utf-8")
            bad_store = tmp / "badstore.json"
            bad_store.write_text('{"items": []}', encoding="utf-8")
            ok_input = ROOT / "fixtures/cases/ok-login/input.json"
            for input_path, store_path in ((bad_input, tmp / "s1.json"), (ok_input, bad_store)):
                with self.subTest(input=input_path.name):
                    report_path = tmp / "report.json"
                    proc = subprocess.run(
                        [
                            sys.executable, "-m", "sshcertx", "admit",
                            "--input", str(input_path),
                            "--keys", str(ROOT / "fixtures/keys.json"),
                            "--policy", str(ROOT / "fixtures/policy.json"),
                            "--store", str(store_path),
                            "--now", "2026-06-18T12:00:00Z",
                            "--report", str(report_path),
                        ],
                        cwd=ROOT, capture_output=True, text=True,
                    )
                    self.assertEqual(proc.returncode, 2)
                    self.assertFalse(report_path.exists())


if __name__ == "__main__":
    unittest.main()
