import unittest

from pwnhunter.models import Vulnerability, VulnType


class TestVulnerabilityToDict(unittest.TestCase):
    def test_offset_zero_is_preserved(self):
        """Regression test for the original bug: `hex(x) if x else None`
        turned a perfectly valid offset of 0 into None because 0 is falsy
        in Python. Must use `is not None` instead."""
        vuln = Vulnerability(
            vuln_type=VulnType.SHELLCODE_EXEC,
            function="<shellcode>",
            location="/bin/whatever",
            description="test",
            severity="CRITICAL",
            offset=0,
        )
        d = vuln.to_dict()
        self.assertEqual(d["offset"], "0x0")

    def test_offset_none_stays_none(self):
        vuln = Vulnerability(
            vuln_type=VulnType.PIE_BYPASS,
            function="N/A",
            location="/bin/whatever",
            description="test",
            severity="HIGH",
            offset=None,
        )
        self.assertIsNone(vuln.to_dict()["offset"])

    def test_offset_nonzero(self):
        vuln = Vulnerability(
            vuln_type=VulnType.ROP_GADGET,
            function="<gadget>",
            location="/bin/whatever",
            description="test",
            severity="INFO",
            offset=0x401234,
        )
        self.assertEqual(vuln.to_dict()["offset"], "0x401234")

    def test_severity_rank_orders_correctly(self):
        sevs = ["INFO", "CRITICAL", "MEDIUM", "LOW", "HIGH"]
        vulns = [
            Vulnerability(VulnType.UNCATEGORIZED, "f", "loc", "d", s) for s in sevs
        ]
        ranked = sorted(vulns, key=lambda v: v.severity_rank())
        self.assertEqual([v.severity for v in ranked],
                          ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])


if __name__ == "__main__":
    unittest.main()
