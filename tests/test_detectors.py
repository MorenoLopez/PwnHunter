import unittest

from pwnhunter.detectors.dangerous_functions import DangerousFunctionDetector
from pwnhunter.detectors.heap import HeapDetector
from pwnhunter.detectors.rop_gadgets import RopGadgetDetector
from pwnhunter.detectors.security_bypass import SecurityBypassDetector
from pwnhunter.detectors.shellcode import ShellcodeDetector
from pwnhunter.models import BinaryInfo, VulnType
from pwnhunter.scan_context import ScanContext


def make_ctx(**binary_info_kwargs):
    info = BinaryInfo(path="/tmp/fake", format="ELF", **binary_info_kwargs)
    return ScanContext(binary_path="/tmp/fake", raw_data=b"", binary_info=info)


class TestSecurityBypassDetector(unittest.TestCase):
    def setUp(self):
        self.detector = SecurityBypassDetector()

    def test_fully_hardened_binary_has_no_findings_except_rpath_check(self):
        ctx = make_ctx(pie=True, nx=True, canary=True, relro="Full", fortify=True,
                        rpath=False, runpath=False)
        findings = self.detector.run(ctx)
        self.assertEqual(findings, [])

    def test_weak_binary_flags_everything(self):
        ctx = make_ctx(pie=False, nx=False, canary=False, relro="No", fortify=False)
        findings = self.detector.run(ctx)
        types = {f.vuln_type for f in findings}
        self.assertIn(VulnType.PIE_BYPASS, types)
        self.assertIn(VulnType.NX_BYPASS, types)
        self.assertIn(VulnType.STACK_CANARY, types)
        self.assertIn(VulnType.RELRO_BYPASS, types)
        self.assertIn(VulnType.FORTIFY_BYPASS, types)
        nx_finding = next(f for f in findings if f.vuln_type == VulnType.NX_BYPASS)
        self.assertEqual(nx_finding.severity, "CRITICAL")

    def test_non_elf_is_skipped(self):
        ctx = make_ctx()
        ctx.binary_info.format = "PE"
        self.assertEqual(self.detector.run(ctx), [])


class TestDangerousFunctionDetector(unittest.TestCase):
    def test_detects_import(self):
        ctx = make_ctx(imports=["gets", "puts", "strcpy"])
        findings = DangerousFunctionDetector().run(ctx)
        funcs = {f.function for f in findings}
        self.assertIn("gets", funcs)
        self.assertIn("strcpy", funcs)
        self.assertNotIn("puts", funcs)  # not in the dangerous-function table

    def test_detects_versioned_import_suffix(self):
        # Real ELF imports often look like "gets@GLIBC_2.2.5"
        ctx = make_ctx(imports=["gets@GLIBC_2.2.5"])
        findings = DangerousFunctionDetector().run(ctx)
        self.assertTrue(any(f.function == "gets" for f in findings))

    def test_detects_disassembly_call(self):
        ctx = make_ctx(imports=[])
        ctx.disassembly = [(0x401000, "call", "strcpy")]
        findings = DangerousFunctionDetector().run(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].offset, 0x401000)


class TestHeapDetector(unittest.TestCase):
    def test_malloc_and_free_produce_one_info_note_not_two_vulnerabilities(self):
        """Regression test: the original script flagged malloc+free usage as
        a MEDIUM 'use-after-free' AND a separate MEDIUM 'double-free' just
        for using free() - i.e. on every normal C program. We now expect a
        single INFO-level note instead."""
        ctx = make_ctx(imports=["malloc", "free"])
        findings = HeapDetector().run(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "INFO")
        self.assertEqual(findings[0].vuln_type, VulnType.HEAP_USAGE)

    def test_no_heap_functions_no_findings(self):
        ctx = make_ctx(imports=["puts", "exit"])
        self.assertEqual(HeapDetector().run(ctx), [])

    def test_large_allocation_string_detected(self):
        ctx = make_ctx(imports=[])
        ctx.binary_info.strings = [(0x100, "malloc(99999)")]
        findings = HeapDetector().run(ctx)
        self.assertTrue(any(f.vuln_type == VulnType.HEAP_OVERFLOW for f in findings))


class TestRopGadgetDetector(unittest.TestCase):
    def test_finds_pop_rdi_ret_on_x86_64(self):
        ctx = make_ctx(arch="EM_X86_64")
        ctx.disassembly = [
            (0x1000, "pop", "rdi"),
            (0x1002, "ret", ""),
        ]
        findings = RopGadgetDetector().run(ctx)
        self.assertTrue(any(f.details.get("gadget_type") == "pop_rdi" for f in findings))

    def test_does_not_apply_x86_patterns_to_arm(self):
        """Regression test: applying x86 register-name regexes to ARM
        disassembly used to silently find nothing while looking like full
        coverage. We now explicitly only use patterns registered for the
        detected architecture family."""
        ctx = make_ctx(arch="EM_ARM")
        # This is x86 syntax, not real ARM disasm, but the point is to prove
        # the x86-only "pop rdi ; ret" pattern is never even attempted.
        ctx.disassembly = [
            (0x1000, "pop", "rdi"),
            (0x1002, "ret", ""),
        ]
        findings = RopGadgetDetector().run(ctx)
        self.assertEqual(findings, [])

    def test_unknown_arch_returns_nothing(self):
        ctx = make_ctx(arch="EM_UNKNOWN_999")
        ctx.disassembly = [(0x1000, "ret", "")]
        self.assertEqual(RopGadgetDetector().run(ctx), [])

    def test_arm_pop_pc_epilogue_is_detected(self):
        """Regression test for a real bug found after the first refactor:
        ARM 32-bit has no 'ret'/'retn' mnemonic at all - it returns via
        'pop {.., pc}', 'bx lr', etc. An earlier fix added ARM regex
        patterns but still gated the whole detector on RET_MNEMONICS=
        ('ret','retn'), so those patterns were unreachable dead code. Real
        ARM disassembly produced zero findings despite "ARM support"."""
        ctx = make_ctx(arch="EM_ARM")
        ctx.disassembly = [
            (0x1000, "mov", "r0, r1"),
            (0x1004, "pop", "{r4, pc}"),
        ]
        findings = RopGadgetDetector().run(ctx)
        self.assertTrue(any(f.details.get("gadget_type") == "pop_pc" for f in findings))

    def test_arm_bx_lr_epilogue_is_detected(self):
        ctx = make_ctx(arch="EM_ARM")
        ctx.disassembly = [
            (0x2000, "mov", "r0, #0"),
            (0x2004, "bx", "lr"),
        ]
        findings = RopGadgetDetector().run(ctx)
        self.assertTrue(any(f.details.get("gadget_type") == "bx_lr" for f in findings))

    def test_arm64_ret_alone_is_not_flagged(self):
        """A bare 'ret' on its own is not interesting (every function ends
        in one) - same convention as x86_64, which only flags 'leave; ret'
        combos, never a bare ret."""
        ctx = make_ctx(arch="EM_AARCH64")
        ctx.disassembly = [(0x3000, "mov", "x0, x1"), (0x3004, "ret", "")]
        self.assertEqual(RopGadgetDetector().run(ctx), [])

    def test_arm64_ldp_ret_combo_is_detected(self):
        ctx = make_ctx(arch="EM_AARCH64")
        ctx.disassembly = [(0x4000, "ldp", "x29, x30, [sp]"), (0x4004, "ret", "")]
        findings = RopGadgetDetector().run(ctx)
        self.assertTrue(any(f.details.get("gadget_type") == "ldp_ret" for f in findings))


class TestShellcodeDetector(unittest.TestCase):
    def test_detects_bin_sh_string(self):
        ctx = ScanContext(binary_path="/tmp/x", raw_data=b"AAAA/bin/shBBBB",
                           binary_info=BinaryInfo(path="/tmp/x"))
        findings = ShellcodeDetector().run(ctx)
        self.assertTrue(any("bin/sh" in f.description for f in findings))

    def test_generic_two_byte_opcode_is_low_confidence(self):
        ctx = ScanContext(binary_path="/tmp/x", raw_data=b"\x0f\x05",
                           binary_info=BinaryInfo(path="/tmp/x"))
        findings = ShellcodeDetector().run(ctx)
        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, "INFO")


if __name__ == "__main__":
    unittest.main()
