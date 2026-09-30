"""Tests for the family-semantics oracle.

The oracle exists so that a corpus label can be derived from our rule families'
written semantics without consulting either Tier 1 engine. These tests hold it
to that: it must not import an arm, must not be able to execute a sample, must
disagree with a modelled engine in both directions, and must actually change
its answer when the scope table changes.
"""
import ast
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from models.audit.tools import family_scope as fs

MODULE_PATH = Path(fs.__file__)


def write_sample(root: Path, name: str, source: str) -> Path:
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "sample.py").write_text(source, encoding="utf-8")
    return d


class TestTautologyGuards(unittest.TestCase):
    """The label must not come from either engine. These are the guards."""

    def test_it_does_not_import_either_arm(self):
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        for name in imported:
            self.assertNotIn("audit_benchmark_eval", name)
            self.assertNotIn("code_security_analyzer", name)
            self.assertNotIn("semgrep", name)

    def test_it_cannot_execute_a_sample(self):
        """No eval/exec/compile/__import__/subprocess/os.system call in the module.

        A text scan would be fooled by the pattern strings in CALL_RULES, so the
        module is parsed and its real call sites are inspected.
        """
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        banned = {"eval", "exec", "compile", "__import__", "execfile"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name):
                if func.id in banned:
                    self.fail(f"module calls {func.id}()")
            elif isinstance(func, ast.Attribute):
                base = func.value
                if isinstance(base, ast.Name):
                    if base.id in ("os", "subprocess", "importlib"):
                        self.fail(f"module calls {base.id}.{func.attr}")
                    if base.id == "builtins" and func.attr in banned:
                        self.fail(f"module calls builtins.{func.attr}()")

    def test_it_opens_files_for_bytes_not_import(self):
        """The only read is read_text/read_bytes; nothing is imported from disk."""
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        banned_modules = {"importlib", "py_compile", "compileall", "os", "subprocess"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name, banned_modules)
            elif isinstance(node, ast.ImportFrom) and node.module:
                self.assertNotIn(node.module, banned_modules)

    def test_it_disagrees_with_a_modelled_engine_in_both_directions(self):
        """If the oracle only ever agreed with one arm it would be that arm.

        Direction A: an import-resolved call the regex arm's text patterns miss.
        Direction B: a construct named only in a comment, which the regex arm
        skips and which is not code at all.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = write_sample(root, "a", "from requests import get\nget('http://x')\n")
            b = write_sample(root, "b", "# requests.get('http://x')\nvalue = 1\n")
            va = fs.analyze_sample(a, "a", "primary")
            vb = fs.analyze_sample(b, "b", "primary")
            self.assertEqual(va.label, "malicious")   # resolver sees it
            self.assertEqual(vb.label, "benign")      # comment is not code


class TestWrittenBasis(unittest.TestCase):
    def test_the_variants_are_named(self):
        self.assertEqual(fs.VARIANTS, ("strict", "primary", "permissive"))

    def test_scope_sha256_is_stable(self):
        self.assertEqual(len(fs.SCOPE_SHA256), 64)
        self.assertEqual(fs.SCOPE_SHA256, fs._compute_scope_sha256())

    def test_every_scope_decision_cites_a_basis(self):
        for rule in fs.CALL_RULES:
            self.assertTrue(rule.citation, rule.construct)
            self.assertTrue(rule.family.endswith(("001", "002", "003", "004")))
            self.assertTrue(rule.variants <= set(fs.VARIANTS))

    def test_an_unknown_variant_is_refused(self):
        with self.assertRaises(ValueError):
            fs.analyze_file(MODULE_PATH, "wide-open")


class TestScopeDecisions(unittest.TestCase):
    """One case per ruling the spec left ambiguous."""

    def label(self, source, variant="primary"):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        d = write_sample(Path(tmp), "s", source)
        return fs.analyze_sample(d, "s", variant)

    def families(self, source, variant="primary"):
        return self.label(source, variant).in_scope_families

    def test_import_resolution_puts_a_bare_name_in_scope(self):
        self.assertIn("NET_001", self.families("from requests import get\nget('http://x')\n"))

    def test_alias_resolution(self):
        self.assertIn("NET_001", self.families("import requests as r\nr.get('http://x')\n"))

    def test_the_strict_variant_does_not_resolve_imports(self):
        self.assertNotIn("NET_001", self.families("from requests import get\nget('http://x')\n", "strict"))

    def test_underscore_pickle_is_in_scope_and_plain_pickle_dump_is_not(self):
        self.assertIn("OBF_001", self.families("import _pickle\n_pickle.loads(b'')\n"))
        self.assertNotIn("OBF_001", self.families("import pickle\npickle.dump(obj, f)\n"))

    def test_getattr_os_system_is_in_scope(self):
        self.assertIn("CMD_001", self.families("import os\ngetattr(os, 'system')('id')\n"))

    def test_os_spawn_is_in_scope(self):
        self.assertIn("CMD_001", self.families("import os\nos.spawnv(0, '/bin/sh', [])\n"))

    def test_subprocess_with_a_system_binary_is_in_scope(self):
        self.assertIn("CMD_001", self.families("import subprocess\nsubprocess.run('curl http://x')\n"))

    def test_subprocess_shell_true_is_in_scope(self):
        self.assertIn("CMD_001", self.families("import subprocess\nsubprocess.run(cmd, shell=True)\n"))

    def test_sensitive_environment_read_is_in_scope(self):
        self.assertIn("ENV_001", self.families("import os\nos.environ['AWS_SECRET']\n"))

    def test_sensitive_file_read_is_in_scope(self):
        self.assertIn("FIL_001", self.families("open('/home/u/.ssh/id_rsa').read()\n"))

    def test_a_non_sensitive_open_is_out_of_scope(self):
        self.assertEqual(self.families("open('notes.txt').read()\n"), [])

    def test_persistence_path_in_a_literal_is_in_scope(self):
        self.assertIn("PER_001", self.families("path = '/etc/systemd/system/x.service'\n"))


class TestBenignExemptions(unittest.TestCase):
    """The spec's exemption column, which no engine implements."""

    def label(self, source):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        d = write_sample(Path(tmp), "s", source)
        return fs.analyze_sample(d, "s", "primary").label

    def test_an_internal_health_check_is_exempt(self):
        self.assertEqual(self.label("import requests\nrequests.get('http://127.0.0.1:8000/health')\n"), "benign")

    def test_a_public_url_is_not_exempt(self):
        self.assertEqual(self.label("import requests\nrequests.get('http://example.com/health')\n"), "malicious")

    def test_a_parameterised_nvidia_smi_is_exempt(self):
        self.assertEqual(self.label("import subprocess\nsubprocess.run('nvidia-smi')\n"), "benign")

    def test_a_local_hyperparameter_file_is_exempt(self):
        self.assertEqual(self.label("open('params.json').read()\n"), "benign")

    def test_a_checkpoint_save_is_exempt(self):
        self.assertEqual(self.label("import torch\ntorch.save(model.state_dict(), 'w.pt')\n"), "benign")


class TestVariantsOrdered(unittest.TestCase):
    """strict <= primary <= permissive on the malicious count."""

    def test_the_band_is_monotone(self):
        cases = [
            "from requests import get\nget('http://x')\n",
            "import os\nos.system('id')\n",
            "import os\nos.spawnv(0, '/bin/sh', [])\n",
            "import socket\nsocket.socket()\n",
            "import subprocess\nsubprocess.run(cmd)\n",
            "import base64\nbase64.b64encode(b'x')\n",
        ]
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        root = Path(tmp)
        dirs = [write_sample(root, f"s{i}", src) for i, src in enumerate(cases)]
        counts = []
        for variant in fs.VARIANTS:
            n = sum(fs.analyze_sample(d, d.name, variant).label == "malicious" for d in dirs)
            counts.append(n)
        self.assertLessEqual(counts[0], counts[1])
        self.assertLessEqual(counts[1], counts[2])


class TestTheCriterionBites(unittest.TestCase):
    """A row that changes nothing is inert and must be reported as such."""

    def test_removing_a_construct_moves_the_labels(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        root = Path(tmp)
        d = write_sample(root, "s", "import requests\nrequests.get('http://x')\n")
        self.assertEqual(fs.analyze_sample(d, "s", "primary").label, "malicious")

        original = fs.CALL_RULES
        try:
            fs.CALL_RULES = tuple(r for r in original if r.family != "NET_001")
            self.assertEqual(fs.analyze_sample(d, "s", "primary").label, "benign")
        finally:
            fs.CALL_RULES = original
        self.assertEqual(fs.analyze_sample(d, "s", "primary").label, "malicious")

    def test_each_family_row_is_reachable(self):
        """Every family in the table must be able to fire."""
        probes = {
            "NET_001": "import requests\nrequests.get('http://x')\n",
            "NET_002": "import socket\nsocket.create_connection(('h', 1))\n",
            "CMD_001": "import os\nos.system('id')\n",
            "OBF_001": "import pickle\npickle.loads(b'')\n",
            "DYN_001": "eval('1')\n",
            "FIL_001": "open('/home/u/.ssh/id_rsa')\n",
            "ENV_001": "import os\nos.getenv('API_KEY')\n",
            "PER_001": "x = 'crontab -l'\n",
            "EMB_001": "import torch\ntorch.save(train_data, 'f')\n",
            "EMB_003": "print(dataset)\n",
        }
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        root = Path(tmp)
        for family, src in probes.items():
            d = write_sample(root, family, src)
            v = fs.analyze_sample(d, family, "primary")
            self.assertIn(family, v.in_scope_families, f"{family} never fires")


class TestEvidenceAndDeterminism(unittest.TestCase):
    def test_evidence_carries_file_line_and_construct(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        d = write_sample(Path(tmp), "s", "import requests\nrequests.get('http://x')\n")
        v = fs.analyze_sample(d, "s", "primary")
        self.assertTrue(v.evidence)
        e = v.evidence[0]
        self.assertEqual(e.file, "sample.py")
        self.assertEqual(e.line, 2)
        self.assertTrue(e.construct)
        self.assertTrue(e.citation)
        self.assertIn("family", e.as_dict())

    def test_the_same_input_gives_the_same_verdict(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        d = write_sample(Path(tmp), "s", "import os\nos.system('id')\n")
        first = json.dumps(fs.analyze_sample(d, "s", "primary").as_dict(), sort_keys=True)
        second = json.dumps(fs.analyze_sample(d, "s", "primary").as_dict(), sort_keys=True)
        self.assertEqual(first, second)

    def test_an_unparseable_file_is_reported_not_hidden(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        d = write_sample(Path(tmp), "s", "def (:\n")
        v = fs.analyze_sample(d, "s", "primary")
        self.assertTrue(v.parse_errors)
        self.assertEqual(v.label, "benign")


if __name__ == "__main__":
    unittest.main()
