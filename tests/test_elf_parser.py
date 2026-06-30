import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from pwnhunter.elf_parser import MinimalELF, ELFParseError, PT_GNU_STACK, PT_GNU_RELRO

FIXTURE_C = Path(__file__).parent / "fixtures" / "vuln.c"


@unittest.skipUnless(shutil.which("gcc"), "gcc not available")
class TestMinimalELF(unittest.TestCase):
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

    def _load(self, path):
        with open(path, "rb") as f:
            return MinimalELF(f.read())

    def test_rejects_non_elf(self):
        with self.assertRaises(ELFParseError):
            MinimalELF(b"not an elf file at all")

    def test_weak_binary_flags(self):
        elf = self._load(self.weak_path)
        self.assertEqual(elf.machine_name, "EM_X86_64")
        self.assertTrue(elf.is_64)
        self.assertFalse(elf.is_pie_or_shared, "compiled with -no-pie")

        stack = elf.get_segment(PT_GNU_STACK)
        self.assertIsNotNone(stack)
        self.assertTrue(stack.p_flags & 0x1, "compiled with -z execstack, should be executable")

    def test_hardened_binary_flags(self):
        elf = self._load(self.hardened_path)
        self.assertTrue(elf.is_pie_or_shared, "compiled with -pie")

        stack = elf.get_segment(PT_GNU_STACK)
        self.assertIsNotNone(stack)
        self.assertFalse(stack.p_flags & 0x1, "no execstack requested, should be NX")

        self.assertIsNotNone(elf.get_segment(PT_GNU_RELRO))
        self.assertTrue(elf.has_bind_now(), "linked with -z now")

    def test_imports_found_via_dynsym(self):
        elf = self._load(self.weak_path)
        dynsyms = elf.dynamic_symbols()
        names = {s.name for s in dynsyms if s.is_undefined}
        for expected in ("gets", "strcpy", "malloc", "free", "system"):
            self.assertIn(expected, names)

    def test_fortify_symbols_found(self):
        elf = self._load(self.hardened_path)
        dynsyms = elf.dynamic_symbols()
        names = {s.name for s in dynsyms if s.is_undefined}
        chk_symbols = {n for n in names if n.endswith("_chk")}
        self.assertTrue(chk_symbols, "expected __*_chk symbols in a _FORTIFY_SOURCE build")

    def test_has_symtab_unstripped(self):
        elf = self._load(self.weak_path)
        self.assertTrue(elf.has_symtab())
        funcs = [s for s in elf.static_symbols() if s.name == "vuln" and s.is_function]
        self.assertTrue(funcs, "local function 'vuln' should be present in .symtab")


if __name__ == "__main__":
    unittest.main()
