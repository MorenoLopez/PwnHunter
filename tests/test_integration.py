import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pwnhunter import PwnHunter, VulnType
from pwnhunter.cli import main as cli_main

FIXTURE_C = Path(__file__).parent / "fixtures" / "vuln.c"


@unittest.skipUnless(shutil.which("gcc"), "gcc not available")
class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="pwnhunter_test_")
        cls.weak_path = str(Path(cls.tmpdir) / "vuln_weak")
        cls.hardened_path = str(Path(cls.tmpdir) / "vuln_hardened")

        subprocess.run(
            ["gcc", "-fno-stack-protector", "-z", "execstack", "-no-pie",
             "-o", cls.weak_path, str(FIXTURE_C), "-w"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["gcc", "-fstack-protector-all", "-D_FORTIFY_SOURCE=2", "-O1",
             "-pie", "-fpic", "-Wl,-z,relro,-z,now",
             "-o", cls.hardened_path, str(FIXTURE_C), "-w"],
            check=True, capture_output=True,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            PwnHunter("/no/such/binary/here")

    def test_full_scan_weak_binary_does_not_crash_and_flags_issues(self):
        hunter = PwnHunter(self.weak_path)
        report = hunter.analyze()

        self.assertEqual(report["binary_info"]["format"], "ELF")
        self.assertEqual(report["binary_info"]["architecture"], "EM_X86_64")
        self.assertGreater(report["summary"]["total_vulnerabilities"], 0)

        types = {v["type"] for v in report["vulnerabilities"]}
        self.assertIn("NX_BYPASS", types)
        self.assertIn("PIE_BYPASS", types)
        self.assertIn("STACK_CANARY", types)
        funcs = {v["function"] for v in report["vulnerabilities"]}
        self.assertIn("gets", funcs)
        self.assertIn("strcpy", funcs)

        # report must be JSON-serialisable (this also exercises the offset=0 fix path)
        json.dumps(report)

    def test_full_scan_hardened_binary_has_fewer_security_bypasses(self):
        hardened = PwnHunter(self.hardened_path).analyze()
        weak = PwnHunter(self.weak_path).analyze()

        hardened_bypasses = sum(
            1 for v in hardened["vulnerabilities"]
            if v["type"] in ("PIE_BYPASS", "NX_BYPASS", "STACK_CANARY", "FORTIFY_BYPASS")
        )
        weak_bypasses = sum(
            1 for v in weak["vulnerabilities"]
            if v["type"] in ("PIE_BYPASS", "NX_BYPASS", "STACK_CANARY", "FORTIFY_BYPASS")
        )
        self.assertLess(hardened_bypasses, weak_bypasses)

    def test_min_severity_filtering(self):
        hunter = PwnHunter(self.weak_path)
        hunter.analyze()
        from pwnhunter.report import build_report
        full = build_report(hunter.binary_info, hunter.vulnerabilities)
        filtered = build_report(hunter.binary_info, hunter.vulnerabilities, min_severity="HIGH")
        self.assertLessEqual(filtered["summary"]["total_vulnerabilities"],
                              full["summary"]["total_vulnerabilities"])
        for v in filtered["vulnerabilities"]:
            self.assertIn(v["severity"], ("CRITICAL", "HIGH"))

    def test_cli_json_output_to_file(self):
        out_path = str(Path(self.tmpdir) / "report.json")
        rc = cli_main([self.weak_path, "--json", "-o", out_path])
        self.assertEqual(rc, 0)
        with open(out_path) as f:
            data = json.load(f)
        self.assertIn("vulnerabilities", data)

    def test_cli_strings_mode(self):
        rc = cli_main([self.weak_path, "--strings"])
        self.assertEqual(rc, 0)

    def test_cli_handles_missing_binary_gracefully(self):
        rc = cli_main(["/no/such/binary"])
        self.assertEqual(rc, 1)

    def test_no_heap_double_counting_regression(self):
        """End-to-end version of the heap-detector regression test: a
        normal malloc/free program must not show up as a confirmed
        UAF + double-free pair of vulnerabilities."""
        report = PwnHunter(self.weak_path).analyze()
        heap_usage = [v for v in report["vulnerabilities"] if v["type"] == "HEAP_USAGE"]
        self.assertEqual(len(heap_usage), 1)
        self.assertEqual(heap_usage[0]["severity"], "INFO")


if __name__ == "__main__":
    unittest.main()
