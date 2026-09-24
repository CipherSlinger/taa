# tests/test_holdout_corpus.py
"""Build the holdout corpus from third-party sources.

The corpus decides the engine comparison, so its construction has to be
mechanical and its rules have to be the ones that were frozen before any
holdout data existed. Those rules were frozen in plan section 12.2, and the
window definition in section 4.2: a sample is the innermost def/class holding
the annotated statement, with module-level annotations dropped and counted.

Three things are worth stating because they are easy to get backwards:

* A semgrep annotation labels the line *below* it, so the enclosing scope is
  looked up from the following line, and the window must contain that line or
  the ground truth is not in the sample.
* The window also has to contain the annotation itself, or the fragment is a
  sample nobody downstream can check the label of.
* A fragment carrying both `# ruleid:` and `# ok:` has no single label. Such a
  window is dropped and counted rather than resolved by preference.
"""
import ast
import json
import tempfile
import unittest
from pathlib import Path

from models.audit.tools import audit_benchmark_eval as ev
from models.audit.tools import holdout_corpus as hc


class TestFamilyMapping(unittest.TestCase):
    """Upstream semgrep rule ids are translated to our families by lexeme.

    The table is a translation, not a claim that the two rules are the same:
    upstream annotations were written for upstream rules, and we map them so a
    sample can be aggregated under one of ours. An id whose lexemes name no
    family is left unmapped, and unmapped samples are excluded and counted.
    """

    def test_command_execution_lexemes_map_to_cmd_001(self):
        for rule_id in (
            "python.lang.security.audit.dangerous-system-call-audit.dangerous-system-call-audit",
            "python.lang.security.audit.dangerous-os-exec-audit.dangerous-os-exec-audit",
            "dangerous-spawn-process-audit",
            "dangerous-subprocess-use-audit",
            "subprocess-shell-true",
            "python-reverse-shell",
            "paramiko-exec-command",
            "unchecked-subprocess-call",
            "system-wildcard-detected",
        ):
            with self.subTest(rule_id=rule_id):
                self.assertEqual(hc.family_of(rule_id), "CMD_001")

    def test_network_lexemes_split_between_request_and_socket(self):
        for rule_id in ("insecure-urlopen", "insecure-urlretrieve", "httpsconnection-detected",
                        "http-not-https-connection", "insecure-request-object",
                        "python.requests.best-practice.use-request-json-shortcut",
                        "no-auth-over-http"):
            with self.subTest(rule_id=rule_id):
                self.assertEqual(hc.family_of(rule_id), "NET_001")
        for rule_id in ("socket-shutdown-close", "telnetlib", "ssl-wrap-socket-is-deprecated"):
            with self.subTest(rule_id=rule_id):
                self.assertEqual(hc.family_of(rule_id), "NET_002")

    def test_dynamic_and_payload_lexemes(self):
        for rule_id in ("eval-detected", "exec-detected",
                        "python37-compatibility-importlib"):
            with self.subTest(rule_id=rule_id):
                self.assertEqual(hc.family_of(rule_id), "DYN_001")
        self.assertEqual(hc.family_of("avoid-pickle"), "OBF_001")

    def test_a_rule_naming_no_family_is_unmapped(self):
        """Most of the upstream python corpus is like this, and it is excluded.

        Mapping by a lexeme that is not in the table must not guess: a wrong
        family would attribute a sample to a rule that never sees it.
        """
        for rule_id in ("insecure-hash-algorithm-md5", "sqlalchemy-execute-raw-query",
                        "flask-deprecated-apis", "insecure-file-permissions"):
            with self.subTest(rule_id=rule_id):
                self.assertIsNone(hc.family_of(rule_id))

    def test_a_bare_lexeme_word_does_not_match_inside_an_unrelated_id(self):
        """`eval` inside another word is not `eval-detected`.

        The lexemes are chosen to be specific for exactly this reason: a loose
        table would silently sweep unrelated rules into a family.
        """
        self.assertIsNone(hc.family_of("django-using-request-post-after-is-valid"))


ANNOTATED = """\
import os

def run(cmd):
    # ruleid: dangerous-system-call-audit
    os.system(cmd)

def safe(cmd):
    # ok: dangerous-system-call-audit
    subprocess.run(["ls", cmd])
"""


def windows_of(text):
    return list(hc.extract_file(text).windows)


class TestWindowExtraction(unittest.TestCase):
    """The frozen window: the innermost def/class holding the labelled line."""

    def test_the_window_is_the_enclosing_function(self):
        windows = windows_of(ANNOTATED)
        self.assertEqual([(w.start, w.end) for w in windows], [(3, 5), (7, 9)])
        first = windows[0]
        self.assertEqual(first.kind, "ruleid")
        self.assertEqual(first.annotated_rule, "dangerous-system-call-audit")
        self.assertEqual(first.family, "CMD_001")
        self.assertEqual(first.label, "malicious")
        self.assertEqual(windows[1].label, "benign")

    def test_the_window_contains_the_line_the_annotation_labels(self):
        """Losing the labelled line loses the ground truth the sample carries."""
        fragment = hc.window_fragment(ANNOTATED.splitlines(), windows_of(ANNOTATED)[0])
        self.assertIn("os.system(cmd)", fragment)

    def test_the_window_contains_its_own_annotation(self):
        """The fragment is the sample; the annotation is the only record of its truth."""
        fragment = hc.window_fragment(ANNOTATED.splitlines(), windows_of(ANNOTATED)[0])
        self.assertIn("# ruleid: dangerous-system-call-audit", fragment)

    def test_an_annotation_at_module_level_has_no_window(self):
        """A whole module is not a sample, so the rule drops these and counts them."""
        result = hc.extract_file("# ruleid: eval-detected\nvalue = 1\n")
        self.assertEqual(result.windows, ())
        self.assertEqual(result.dropped_outside, 1)
        self.assertEqual(result.annotations, 1)

    def test_two_annotations_in_one_function_are_one_window(self):
        """Both statements live in one scope, and the scope is the sample."""
        result = hc.extract_file(
            "def f():\n    # ruleid: eval-detected\n    eval(a)\n"
            "    # ruleid: exec-detected\n    exec(b)\n"
        )
        self.assertEqual([(w.start, w.end) for w in result.windows], [(1, 5)])
        self.assertEqual(result.annotations, 2)
        self.assertEqual(result.dropped_mixed, 0)

    def test_a_window_carrying_both_kinds_is_dropped_and_counted(self):
        """No single label can be given, so it is not resolved by preference.

        The count matters as much as the drop: a corpus that quietly discards
        the samples it cannot label reads as cleaner than it is. The unit
        counted is the window - one dropped window discards every annotation
        that fell in it.
        """
        result = hc.extract_file(
            "def f():\n    # ruleid: eval-detected\n    eval(a)\n"
            "    # ok: exec-detected\n    exec(b)\n"
        )
        self.assertEqual(result.windows, ())
        self.assertEqual(result.dropped_mixed, 1)
        self.assertEqual(result.annotations, 2)

    def test_both_kinds_in_different_functions_are_two_windows(self):
        text = ("def f():\n    # ruleid: eval-detected\n    eval(a)\n\n"
                "def g():\n    # ok: exec-detected\n    exec(b)\n")
        result = hc.extract_file(text)
        self.assertEqual([w.kind for w in result.windows], ["ruleid", "ok"])
        self.assertEqual(result.dropped_mixed, 0)

    def test_an_annotation_above_a_nested_definition_keeps_itself_in_the_window(self):
        """The labelled statement is the `def`, which starts below the annotation.

        Without widening the span by the annotation line the fragment would be a
        sample with no visible label - unauditable, and impossible to attribute
        when the report is read.
        """
        result = hc.extract_file(
            "class C:\n    # ruleid: eval-detected\n    def m(self):\n        eval(a)\n"
        )
        self.assertEqual([(w.start, w.end) for w in result.windows], [(2, 4)])
        fragment = hc.window_fragment(
            "class C:\n    # ruleid: eval-detected\n    def m(self):\n        eval(a)\n".splitlines(),
            result.windows[0],
        )
        self.assertIn("# ruleid: eval-detected", fragment)

    def test_a_line_merely_mentioning_an_annotation_is_not_one(self):
        text = 'NOTE = "# ruleid: eval-detected"\nvalue = 1\n'
        self.assertEqual(windows_of(text), [])

    def test_an_unmapped_annotation_is_returned_with_no_family(self):
        """It is extracted so the build can count it, not silently discarded."""
        windows = windows_of("def f():\n    # ruleid: insecure-hash-algorithm-md5\n    h = md5(x)\n")
        self.assertEqual(len(windows), 1)
        self.assertIsNone(windows[0].family)

    def test_a_file_that_does_not_parse_is_reported_not_read_as_empty(self):
        """An unparseable file is excluded at build time (rule 4), and counted.

        Returning the same thing as a file with no annotations would make the
        two indistinguishable in the build's drop counts.
        """
        result = hc.extract_file("def f(:\n    # ok: eval-detected\n    pass\n")
        self.assertTrue(result.unparseable)
        self.assertEqual(result.windows, ())
        self.assertEqual(result.annotations, 1)

    def test_a_file_with_no_annotations_yields_nothing(self):
        result = hc.extract_file("def f():\n    return 1\n")
        self.assertEqual(result.windows, ())
        self.assertEqual(result.annotations, 0)
        self.assertFalse(result.unparseable)


class TestWindowFragment(unittest.TestCase):
    def test_the_fragment_is_dedented_so_it_can_be_parsed(self):
        text = "def f():\n    # ruleid: eval-detected\n    eval(x)\n"
        fragment = hc.window_fragment(text.splitlines(), windows_of(text)[0])
        self.assertEqual(fragment, "def f():\n    # ruleid: eval-detected\n    eval(x)\n")

    def test_a_trailing_newline_is_kept(self):
        fragment = hc.window_fragment(ANNOTATED.splitlines(), windows_of(ANNOTATED)[0])
        self.assertTrue(fragment.endswith("\n"))

    def test_a_dedented_fragment_of_a_nested_scope_parses(self):
        """The fragment has to be a file: an indented span at module level is not."""
        text = "class C:\n    # ruleid: eval-detected\n    def m(self):\n        eval(a)\n"
        fragment = hc.window_fragment(text.splitlines(), windows_of(text)[0])
        ast.parse(fragment)


class TestBenignExclusions(unittest.TestCase):
    """Rule 1's path hygiene applies to the PyPI arm only.

    The malicious arm deliberately keeps `__init__.py` and `setup.py`: in a
    trojanised package those are where the payload lives, so excluding them
    would discard the malware and keep its packaging.
    """

    def test_benign_paths_that_are_not_the_library_are_excluded(self):
        for path in ("pkg/tests/test_x.py", "pkg/fixtures/data.py", "pkg/examples/demo.py",
                     "pkg/__init__.py", "pkg/test_helpers.py", "pkg/a/__init__.py"):
            with self.subTest(path=path):
                self.assertTrue(hc.is_benign_excluded(path))

    def test_the_exclusion_is_the_frozen_substring_rule(self):
        """Rule 1 names path substrings, so the match is literal, not semantic.

        `test_` is a substring, which also covers `latest_`. That is what the
        frozen rule says, so it is what is implemented; tightening it here would
        be changing a rule to suit a preference, and the report is where a
        reader can see the consequence.
        """
        self.assertTrue(hc.is_benign_excluded("pkg/latest_data.py"))

    def test_library_paths_are_kept(self):
        for path in ("pkg/core.py", "pkg/sub/module.py", "pkg/utils/parse.py",
                     "pkg/testing/x.py"):
            with self.subTest(path=path):
                self.assertFalse(hc.is_benign_excluded(path))


def sample(sample_id="s-001", family=hc.FAMILY_PYPI, label="benign", **overrides):
    fields = dict(
        sample_id=sample_id, base_project="attrs-26.1.0", family=family, label=label,
        text="import os\n\n\ndef f():\n    return 1\n",
        provenance={"source": "pypi-sdist", "path": "attrs-26.1.0/src/attr/_make.py"},
    )
    fields.update(overrides)
    return hc.Sample(**fields)


class TestSampleContract(unittest.TestCase):
    """The shape the evaluator requires, read off its loader rather than assumed.

    These pin the two facts that are silent when wrong: an entry with a field the
    evaluator does not declare raises instead of being ignored, and the sample
    directory is resolved as `<root>/<relative_path>` with the parity proof's
    traversal only recognising one and two level layouts.
    """

    def test_a_corpus_list_entry_carries_only_declared_fields(self):
        entry = sample().corpus_list_entry()
        self.assertEqual(set(entry), set(hc.CORPUS_LIST_FIELDS))

    def test_the_relative_path_is_two_levels(self):
        """One level would not be found by the parity proof's traversal."""
        self.assertEqual(sample().relative_path, "attrs-26.1.0/s-001")

    def test_the_metadata_names_the_file_attribution_is_matched_on(self):
        """Attribution compares a basename and a rule id; the line is not read."""
        meta = sample(
            family="CMD_001", label="malicious",
            primary_attack_finding={"file": hc.SAMPLE_FILENAME, "rule_id": "CMD_001", "line": 3},
        ).sample_metadata()
        self.assertEqual(meta["primary_attack_finding"]["rule_id"], "CMD_001")
        self.assertEqual(meta["label"], "malicious")
        self.assertIn("source", meta)

    def test_the_metadata_states_no_expected_final(self):
        """Nothing reads it from here, and the run reports its own value.

        The evaluator scores on a corpus list entry's label and defaults the
        expectation to UNSPECIFIED for a declared corpus, so a value here would
        be a claim nothing reads that contradicts the report.
        """
        self.assertNotIn("expected_final", sample().sample_metadata())


class TestWriteCorpus(unittest.TestCase):
    def test_it_writes_one_file_and_one_record_per_sample(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hc.write_corpus(root, [sample()])

            sample_dir = root / "attrs-26.1.0" / "s-001"
            self.assertEqual(sorted(p.name for p in sample_dir.iterdir()),
                             ["sample.json", hc.SAMPLE_FILENAME])
            self.assertIn("def f()", (sample_dir / hc.SAMPLE_FILENAME).read_text())

    def test_it_writes_the_corpus_list_the_evaluator_reads(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hc.write_corpus(root, [sample(), sample(sample_id="s-002", label="malicious")])

            payload = json.loads((root / "corpus-list.json").read_text())
            self.assertEqual([row["sample_id"] for row in payload["samples"]], ["s-001", "s-002"])
            self.assertEqual(payload["samples"][1]["relative_path"], "attrs-26.1.0/s-002")

    def test_the_written_corpus_list_is_accepted_by_the_evaluator(self):
        """The contract is the evaluator's, so the evaluator is what checks it.

        Reading the loader and copying its field list is not the same as the
        loader accepting what this module writes.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hc.write_corpus(root, [sample(), sample(sample_id="s-002", label="malicious",
                                                    family="CMD_001")])
            specs = ev.load_corpus_list(root / "corpus-list.json")

        self.assertEqual([spec.sample_id for spec in specs], ["s-001", "s-002"])
        self.assertEqual(specs[1].label, "malicious")
        self.assertEqual(specs[0].relative_path, "attrs-26.1.0/s-001")

    def test_a_repeated_sample_id_is_refused(self):
        """The evaluator indexes pairs by it, so a repeat drops a pair silently."""
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError) as caught:
                hc.write_corpus(Path(td), [sample(), sample()])
        self.assertIn("duplicate sample_id", str(caught.exception))

    def test_an_empty_sample_is_refused(self):
        """An empty file scores as a file with nothing in it, not as a failure."""
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError) as caught:
                hc.write_corpus(Path(td), [sample(text="\n\n")])
        self.assertIn("empty", str(caught.exception))


class TestCorpusCounts(unittest.TestCase):
    def test_it_counts_by_label_family_and_source(self):
        counts = hc.corpus_counts([
            sample(),
            sample(sample_id="s-002", family="CMD_001", label="malicious",
                   provenance={"source": "semgrep-rules"}),
            sample(sample_id="s-003", family="CMD_001", label="malicious",
                   provenance={"source": "semgrep-rules"}),
        ])
        self.assertEqual(counts["total"], 3)
        self.assertEqual(counts["by_label"], {"malicious": 2, "benign": 1})
        self.assertEqual(counts["by_family"]["CMD_001"], {"malicious": 2})
        self.assertEqual(counts["by_source"], {"pypi-sdist": 1, "semgrep-rules": 2})

    def test_a_family_with_no_samples_is_simply_absent(self):
        """The report distinguishes 'no samples' from 'not measured', so it needs
        the per-family table to be exactly what was built, not padded."""
        counts = hc.corpus_counts([sample()])
        self.assertNotIn("NET_002", counts["by_family"])
        self.assertEqual(counts["by_label"], {"malicious": 0, "benign": 1})


class TestProvenance(unittest.TestCase):
    def test_it_carries_the_upstream_record_for_every_sample(self):
        payload = hc.provenance_payload(
            sources=[{"name": "pypi-sdist", "revision": "pinned versions"}],
            samples=[sample()],
            drops={"dropped_outside": 758, "dropped_mixed": 51},
        )
        self.assertEqual(payload["sources"][0]["name"], "pypi-sdist")
        self.assertEqual(payload["drops"]["dropped_outside"], 758)
        row = payload["samples"][0]
        self.assertEqual(row["sample_id"], "s-001")
        self.assertEqual(row["path"], "attrs-26.1.0/src/attr/_make.py")
        self.assertTrue(payload["built_at"].endswith("Z"))


TREE_FILE = """\
import subprocess

def handler(cmd):
    # ruleid: dangerous-subprocess-use-audit
    subprocess.call(cmd, shell=True)

def other(cmd):
    # ok: dangerous-os-exec-audit
    subprocess.call(["/bin/echo", cmd])
"""

UNMAPPED_FILE = """\
def f(x):
    # ruleid: insecure-hash-algorithm-md5
    return md5(x)
"""


class TestWindowsToSamples(unittest.TestCase):
    """The walk turns a checkout into samples, in path order, outcome-blind.

    Nothing here consults an engine: the selection is the file order and the
    upstream annotation, so the same revision yields the same corpus.
    """

    def _tree(self, tmp, files):
        root = Path(tmp)
        for relpath, text in files.items():
            path = root / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root

    def test_each_labelled_window_becomes_one_sample(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._tree(td, {"python/audit/x.py": TREE_FILE})
            samples, _ = hc.samples_from_windows(root, revision="abc123")

        self.assertEqual([s.label for s in samples], ["malicious", "benign"])
        self.assertEqual([s.family for s in samples], ["CMD_001", "CMD_001"])
        self.assertEqual([s.sample_id for s in samples], ["sr-0001", "sr-0002"])
        self.assertTrue(all(s.base_project == "semgrep-rules" for s in samples))

    def test_the_sample_carries_the_ground_truth_it_was_labelled_by(self):
        """The line is the fragment's numbering, not the upstream file's.

        The sample is a file of its own, so a line number carried over from the
        file it was cut out of would point past the sample's end.
        """
        with tempfile.TemporaryDirectory() as td:
            root = self._tree(td, {"python/audit/x.py": TREE_FILE})
            samples, _ = hc.samples_from_windows(root, revision="abc123")

        first = samples[0]
        self.assertEqual(first.primary_attack_finding,
                         {"file": hc.SAMPLE_FILENAME, "rule_id": "CMD_001", "line": 3})
        self.assertEqual(first.text.splitlines()[2], "    subprocess.call(cmd, shell=True)")
        self.assertIn("# ruleid: dangerous-subprocess-use-audit", first.text)
        self.assertEqual(first.provenance["annotation"], "# ruleid: dangerous-subprocess-use-audit")
        self.assertEqual(first.provenance["annotation_line"], 4)
        self.assertEqual(first.provenance["revision"], "abc123")
        self.assertEqual(first.provenance["path"], "python/audit/x.py")
        self.assertIn("modification", first.provenance)

    def test_a_benign_sample_claims_no_attack_finding(self):
        """There is no finding to attribute; claiming one would invent ground truth."""
        with tempfile.TemporaryDirectory() as td:
            root = self._tree(td, {"python/audit/x.py": TREE_FILE})
            samples, _ = hc.samples_from_windows(root, revision="abc123")

        self.assertIsNone(samples[1].primary_attack_finding)

    def test_an_unmapped_annotation_is_excluded_and_counted(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._tree(td, {"python/audit/x.py": UNMAPPED_FILE})
            samples, drops = hc.samples_from_windows(root, revision="abc123")

        self.assertEqual(samples, [])
        self.assertEqual(drops["unmapped"], 1)
        self.assertEqual(drops["annotations"], 1)

    def test_the_walk_is_in_path_order_so_a_revision_is_reproducible(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._tree(td, {
                "python/b.py": TREE_FILE.replace("def handler", "def handler_b"),
                "python/a.py": TREE_FILE.replace("def handler", "def handler_a"),
            })
            samples, _ = hc.samples_from_windows(root, revision="abc123")

        self.assertEqual([s.provenance["path"] for s in samples],
                         ["python/a.py", "python/a.py", "python/b.py", "python/b.py"])

    def test_the_drops_are_reported_for_every_annotation(self):
        """A build that discards quietly reads as better covered than it is."""
        with tempfile.TemporaryDirectory() as td:
            root = self._tree(td, {
                "python/a.py": TREE_FILE,
                "python/b.py": "# ruleid: eval-detected\nvalue = 1\n",
            })
            _, drops = hc.samples_from_windows(root, revision="abc123")

        self.assertEqual(drops["annotations"], 3)
        self.assertEqual(drops["dropped_outside"], 1)
        self.assertEqual(drops["unmapped"], 0)

    def test_the_samples_it_returns_are_accepted_by_the_writer(self):
        """The two halves meet: what the walk builds is what the corpus takes."""
        with tempfile.TemporaryDirectory() as td:
            root = self._tree(td, {"python/audit/x.py": TREE_FILE})
            samples, _ = hc.samples_from_windows(root, revision="abc123")
            out = Path(td) / "corpus"
            counts = hc.write_corpus(out, samples)

            self.assertEqual(counts["by_label"], {"malicious": 1, "benign": 1})
            self.assertEqual(counts["by_family"], {"CMD_001": {"malicious": 1, "benign": 1}})
            specs = ev.load_corpus_list(out / "corpus-list.json")

        self.assertEqual([spec.family for spec in specs], ["CMD_001", "CMD_001"])


class TestTreeDigest(unittest.TestCase):
    """A content fingerprint, because a tarball checkout cannot verify its own revision.

    The upstream revision string is a claim nothing local can check: the
    directory in hand says nothing about which commit it came from. This is
    what a reader with the same checkout can reproduce.
    """

    def test_it_counts_the_files_it_covers(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.py").write_text("x = 1\n", encoding="utf-8")
            (root / "sub").mkdir()
            (root / "sub" / "b.py").write_text("y = 2\n", encoding="utf-8")
            (root / "notes.txt").write_text("ignored\n", encoding="utf-8")

            digest, count = hc.tree_digest(root)

            self.assertEqual(count, 2)
            self.assertEqual(len(digest), 64)

    def test_the_same_bytes_give_the_same_digest(self):
        with tempfile.TemporaryDirectory() as td:
            first = Path(td) / "one"
            second = Path(td) / "two"
            for root in (first, second):
                root.mkdir()
                (root / "a.py").write_text("x = 1\n", encoding="utf-8")
            self.assertEqual(hc.tree_digest(first), hc.tree_digest(second))

    def test_changed_content_changes_the_digest(self):
        """Otherwise the fingerprint would not notice a drifted checkout."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.py").write_text("x = 1\n", encoding="utf-8")
            before, _ = hc.tree_digest(root)
            (root / "a.py").write_text("x = 2\n", encoding="utf-8")
            after, _ = hc.tree_digest(root)
            self.assertNotEqual(before, after)

    def test_renaming_a_file_changes_the_digest(self):
        """The path is part of what a sample's provenance claims."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.py").write_text("x = 1\n", encoding="utf-8")
            before, _ = hc.tree_digest(root)
            (root / "a.py").rename(root / "b.py")
            after, _ = hc.tree_digest(root)
            self.assertNotEqual(before, after)


if __name__ == "__main__":
    unittest.main()
