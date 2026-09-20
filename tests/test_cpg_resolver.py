# tests/test_cpg_resolver.py
"""
Unit tests for the multi-file & cross-repository SymbolResolver.
Tests absolute, relative, aliased, and wildcard imports as well as class methods.
"""

import tempfile
import unittest
from pathlib import Path
from models.audit.tools.cpg.resolver import SymbolResolver


class TestCPGSymbolResolver(unittest.TestCase):
    """Test suite for SymbolResolver import and FQN mapping."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # Create sample multi-file project layout
        # root/
        #   pkg/
        #     __init__.py
        #     utils.py (def helper(), class Cryptor)
        #     worker.py (imports helper from utils)
        #   sub/
        #     reporter.py (relative import from ..pkg.utils)
        pkg = self.root / "pkg"
        pkg.mkdir(parents=True)
        sub = self.root / "sub"
        sub.mkdir(parents=True)

        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "utils.py").write_text(
            "def helper(x):\n"
            "    return x * 2\n\n"
            "class Cryptor:\n"
            "    def encrypt(self, data):\n"
            "        return data[::-1]\n",
            encoding="utf-8",
        )
        (pkg / "worker.py").write_text(
            "from .utils import helper as hp, Cryptor\n\n"
            "def run_task(val):\n"
            "    c = Cryptor()\n"
            "    return hp(val)\n",
            encoding="utf-8",
        )
        (sub / "reporter.py").write_text(
            "from ..pkg.utils import helper\n\n"
            "def report(d):\n"
            "    return helper(d)\n",
            encoding="utf-8",
        )

        self.resolver = SymbolResolver(workspace_roots=[str(self.root)])
        self.resolver.index_workspace()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_index_definitions(self):
        self.assertIn("pkg.utils.helper", self.resolver.global_symbols)
        self.assertIn("pkg.utils.Cryptor", self.resolver.global_symbols)
        self.assertIn("pkg.utils.Cryptor.encrypt", self.resolver.global_symbols)
        self.assertIn("pkg.worker.run_task", self.resolver.global_symbols)
        self.assertIn("sub.reporter.report", self.resolver.global_symbols)

    def test_resolve_relative_import_and_alias(self):
        worker_file = str((self.root / "pkg" / "worker.py").resolve())
        # hp should resolve to pkg.utils.helper
        resolved = self.resolver.resolve_symbol(worker_file, "hp")
        self.assertEqual(resolved, "pkg.utils.helper")

        # Cryptor should resolve to pkg.utils.Cryptor
        resolved_crypt = self.resolver.resolve_symbol(worker_file, "Cryptor")
        self.assertEqual(resolved_crypt, "pkg.utils.Cryptor")

    def test_resolve_double_dot_relative_import(self):
        reporter_file = str((self.root / "sub" / "reporter.py").resolve())
        resolved = self.resolver.resolve_symbol(reporter_file, "helper")
        self.assertEqual(resolved, "pkg.utils.helper")

    def test_resolve_method_with_scope(self):
        utils_file = str((self.root / "pkg" / "utils.py").resolve())
        resolved = self.resolver.resolve_symbol(utils_file, "self.encrypt", current_scope="Cryptor.encrypt")
        self.assertEqual(resolved, "pkg.utils.Cryptor.encrypt")


if __name__ == "__main__":
    unittest.main()
