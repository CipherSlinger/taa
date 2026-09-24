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

The manifest-backed arms are built from synthetic fixtures only. The real
fixtures include live malware, and a test that read them would execute nothing
but would still put real payload bytes into a test run; the shapes the loaders
read are what matters here, so the fixtures below carry throwaway Python.
"""
import ast
import io
import json
import tarfile
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


class TestPreRegisteredScreen(unittest.TestCase):
    """The two exclusions decided before any holdout data existed.

    Both look at the build, never at a verdict: whether a file parses, and how
    many findings it drew - not what they were or how the run concluded.
    """

    def test_a_sample_on_the_cap_is_excluded_not_just_one_above_it(self):
        """The Go check is `>=`, so sitting exactly on the cap is already truncated."""
        samples = [sample(sample_id=f"s-{n:03d}") for n in (199, 200, 201)]
        counts = {"s-199": 199, "s-200": 200, "s-201": 201}
        kept, excluded = hc.over_static_cap(samples, lambda s: counts[s.sample_id])

        self.assertEqual([s.sample_id for s in kept], ["s-199"])
        self.assertEqual([row["sample_id"] for row in excluded], ["s-200", "s-201"])
        self.assertEqual(excluded[0]["rule"], "static-cap")
        self.assertEqual(excluded[0]["cap"], hc.MAX_STATIC_FINDINGS)

    def test_the_cap_mirrors_the_engine_it_protects_the_proof_from(self):
        """It is the Go engine's number; a drifted copy would let divergences through."""
        self.assertEqual(hc.MAX_STATIC_FINDINGS, 200)

    def test_the_exclusions_are_returned_with_their_counts(self):
        """Dropped quietly, the corpus reads as cleaner than it is."""
        samples = [sample(sample_id="s-1"), sample(sample_id="s-2")]
        _, excluded = hc.over_static_cap(samples, lambda s: 500 if s.sample_id == "s-2" else 3)

        self.assertEqual(excluded, [{"sample_id": "s-2", "rule": "static-cap",
                                     "findings": 500, "cap": 200}])

    def test_it_reads_only_the_count(self):
        """A rule that peeked at findings would be selecting samples by outcome."""
        seen = []

        def counter(s):
            seen.append(s.sample_id)
            return 0

        hc.over_static_cap([sample(sample_id="s-1")], counter)
        self.assertEqual(seen, ["s-1"])

    def test_an_unparseable_sample_is_reported_by_rule_four(self):
        good = sample(sample_id="s-good")
        bad = sample(sample_id="s-bad", text="def f(:\n    pass\n")

        rows = hc.unparseable_samples([good, bad])

        self.assertEqual([row["sample_id"] for row in rows], ["s-bad"])
        self.assertEqual(rows[0]["rule"], "unparseable")


# ----------------------------------------------------------- manifest loading
#
# The three manifest-backed arms. Every fixture here is synthetic and holds
# throwaway Python: the real malicious manifest describes live malware, and a
# test has no reason to read it. What is under test is the shape the loaders
# read and the counts they report, neither of which depends on the payload.

HEX64 = "a" * 64


def write_file(root, relpath, payload):
    path = Path(root) / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, bytes):
        path.write_bytes(payload)
    else:
        path.write_text(payload, encoding="utf-8")
    return path


def make_sdist(path, members):
    """A `.tar.gz` holding exactly the members given, none of them executed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tar:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    return path


def dd_entry(relpath, text, *, extracted_path=None, **overrides):
    """A malicious-manifest entry, hash and coordinates included."""
    fields = dict(
        package="pkg",
        version="1.0.0",
        archive_path="samples/pypi/malicious_intent/pkg/1.0.0/pkg-v1.0.0.zip",
        archive_sha256=HEX64,
        in_archive_path=f"pkg-1.0.0/{relpath}",
        relpath=relpath,
        extracted_path=extracted_path or f"dd/extracted/pkg/1.0.0/{relpath}",
        bytes=len(text.encode("utf-8")),
        sha256=hc.sha256_text(text),
    )
    fields.update(overrides)
    return fields


def sdist_entry(member, archive_filename, archive_bytes, text, **overrides):
    """A benign-manifest entry for one member of one sdist."""
    fields = dict(
        arm=hc.BENIGN_ARM,
        package="attrs",
        version="26.1.0",
        archive_filename=archive_filename,
        path=member,
        url=f"https://files.pythonhosted.org/packages/{archive_filename}",
        archive_sha256_observed=hc.sha256_bytes(archive_bytes),
        archive_sha256_pypi=hc.sha256_bytes(archive_bytes),
        bytes=len(text.encode("utf-8")),
        sha256=hc.sha256_text(text),
    )
    fields.update(overrides)
    return fields


def cq_entry(path, text, *, label_lines=None, **overrides):
    """A near-miss-manifest entry for one downloaded CodeQL file.

    `label_lines` is the manifest's label -> lines map, which is what the
    selection reads a line's two-expectation case out of. An entry that names
    labels without saying which lines they are on is a shape the real manifest
    never has, so the default is the empty map and not a guess.
    """
    fields = dict(
        arm=hc.NEAR_MISS_ARM,
        package="github/codeql",
        version="0" * 40,
        path=path,
        url=f"https://raw.githubusercontent.com/github/codeql/{path}",
        git_blob_sha1="0" * 40,
        bytes=len(text.encode("utf-8")),
        sha256=hc.sha256_text(text),
        label_lines={} if label_lines is None else label_lines,
    )
    fields.update(overrides)
    return fields


def write_reference(root, references):
    return write_file(root, hc.VENDOR_REFERENCE_FILENAME,
                      json.dumps({"references": references}))


class TestVendorReference(unittest.TestCase):
    """The vendored-file map, and every way a reference file can be wrong.

    A reference that is missing, malformed, or ambiguous has to raise. Read
    leniently it would say "nothing is vendored", which silently restores
    exactly the files it exists to remove - and the build would report a clean
    malicious arm that is mostly somebody else's released library.
    """

    def test_it_maps_every_file_hash_to_its_distribution(self):
        with tempfile.TemporaryDirectory() as td:
            path = write_reference(td, [
                {"dist": "attrs", "version": "26.1.0", "url": "https://example.invalid/a",
                 "sdist_sha256": HEX64, "file_sha256": ["1" * 64, "2" * 64],
                 "matched_entries": 2},
                {"dist": "click", "version": "8.4.2", "url": "https://example.invalid/c",
                 "sdist_sha256": "b" * 64, "file_sha256": ["3" * 64], "matched_entries": 1},
            ])
            reference = hc.load_vendor_reference(path)

        self.assertEqual(reference["1" * 64], "attrs==26.1.0")
        self.assertEqual(reference["2" * 64], "attrs==26.1.0")
        self.assertEqual(reference["3" * 64], "click==8.4.2")
        self.assertEqual(len(reference), 3)

    def test_the_sdist_hash_is_not_itself_a_vendored_file(self):
        """It names the distribution's archive, not a file inside it."""
        with tempfile.TemporaryDirectory() as td:
            path = write_reference(td, [
                {"dist": "attrs", "version": "26.1.0", "url": "u", "sdist_sha256": HEX64,
                 "file_sha256": ["1" * 64], "matched_entries": 1},
            ])
            reference = hc.load_vendor_reference(path)
        self.assertNotIn(HEX64, reference)

    def test_a_missing_top_level_key_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = write_file(td, hc.VENDOR_REFERENCE_FILENAME, json.dumps({"files": []}))
            with self.assertRaises(ValueError) as caught:
                hc.load_vendor_reference(path)
        self.assertIn("references", str(caught.exception))

    def test_references_must_be_a_list(self):
        with tempfile.TemporaryDirectory() as td:
            path = write_reference(td, {"attrs": "26.1.0"})
            with self.assertRaises(ValueError) as caught:
                hc.load_vendor_reference(path)
        self.assertIn("must be a list", str(caught.exception))

    def test_a_missing_key_on_a_reference_is_refused(self):
        base = {"dist": "attrs", "version": "26.1.0", "url": "u",
                "sdist_sha256": HEX64, "file_sha256": ["1" * 64], "matched_entries": 1}
        for key in sorted(base):
            with self.subTest(missing=key):
                with tempfile.TemporaryDirectory() as td:
                    reference = {k: v for k, v in base.items() if k != key}
                    path = write_reference(td, [reference])
                    with self.assertRaises(ValueError) as caught:
                        hc.load_vendor_reference(path)
                self.assertIn(repr(key), str(caught.exception))

    def test_a_hash_that_is_not_64_lowercase_hex_is_refused(self):
        bad = ["", "a" * 63, "a" * 65, "A" * 64, "g" * 64, 17, None]
        for value in bad:
            with self.subTest(hash=value):
                with tempfile.TemporaryDirectory() as td:
                    path = write_reference(td, [
                        {"dist": "attrs", "version": "26.1.0", "url": "u",
                         "sdist_sha256": HEX64, "file_sha256": [value], "matched_entries": 1},
                    ])
                    with self.assertRaises(ValueError) as caught:
                        hc.load_vendor_reference(path)
                self.assertIn("64 lowercase hex", str(caught.exception))

    def test_the_sdist_hash_is_validated_too(self):
        with tempfile.TemporaryDirectory() as td:
            path = write_reference(td, [
                {"dist": "attrs", "version": "26.1.0", "url": "u", "sdist_sha256": "NOTAHASH",
                 "file_sha256": ["1" * 64], "matched_entries": 1},
            ])
            with self.assertRaises(ValueError):
                hc.load_vendor_reference(path)

    def test_file_sha256_must_be_a_list(self):
        with tempfile.TemporaryDirectory() as td:
            path = write_reference(td, [
                {"dist": "attrs", "version": "26.1.0", "url": "u", "sdist_sha256": HEX64,
                 "file_sha256": "1" * 64, "matched_entries": 1},
            ])
            with self.assertRaises(ValueError) as caught:
                hc.load_vendor_reference(path)
        self.assertIn("must be a list", str(caught.exception))

    def test_a_hash_two_distributions_claim_is_refused(self):
        """An ambiguous reference is a build error, not a silent pick."""
        with tempfile.TemporaryDirectory() as td:
            path = write_reference(td, [
                {"dist": "attrs", "version": "26.1.0", "url": "u", "sdist_sha256": HEX64,
                 "file_sha256": ["1" * 64], "matched_entries": 1},
                {"dist": "click", "version": "8.4.2", "url": "u", "sdist_sha256": "b" * 64,
                 "file_sha256": ["1" * 64], "matched_entries": 1},
            ])
            with self.assertRaises(ValueError) as caught:
                hc.load_vendor_reference(path)

        self.assertIn("attrs==26.1.0", str(caught.exception))
        self.assertIn("click==8.4.2", str(caught.exception))

    def test_an_empty_reference_list_is_an_empty_map(self):
        """A reference that resolves nothing is legal; it is just not useful."""
        with tempfile.TemporaryDirectory() as td:
            path = write_reference(td, [])
            self.assertEqual(hc.load_vendor_reference(path), {})

    def test_a_document_that_is_not_json_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = write_file(td, hc.VENDOR_REFERENCE_FILENAME, "{not json")
            with self.assertRaises(ValueError) as caught:
                hc.load_vendor_reference(path)
        self.assertIn("not valid JSON", str(caught.exception))


class TestDropVendored(unittest.TestCase):
    def test_it_splits_by_membership_and_keeps_input_order(self):
        reference = {"1" * 64: "attrs==26.1.0"}
        entries = [{"sha256": "1" * 64, "name": "vendored"},
                   {"sha256": "2" * 64, "name": "first"},
                   {"sha256": "3" * 64, "name": "second"}]

        kept, dropped = hc.drop_vendored(entries, reference)

        self.assertEqual([entry["name"] for entry in kept], ["first", "second"])
        self.assertEqual([entry["name"] for entry in dropped], ["vendored"])

    def test_nothing_is_dropped_when_the_reference_is_empty(self):
        entries = [{"sha256": "1" * 64}, {"sha256": "2" * 64}]
        kept, dropped = hc.drop_vendored(entries, {})
        self.assertEqual(len(kept), 2)
        self.assertEqual(dropped, [])


class TestDedupByContent(unittest.TestCase):
    """Byte-identical files are one sample, chosen by a property of the data."""

    def test_identical_content_collapses_to_one_entry(self):
        entries = [{"package": "pkg", "relpath": "a.py", "version": "1", "sha256": "1" * 64},
                   {"package": "pkg", "relpath": "b.py", "version": "1", "sha256": "1" * 64},
                   {"package": "pkg", "relpath": "c.py", "version": "1", "sha256": "2" * 64}]

        kept, dropped = hc.dedup_by_content(entries)

        self.assertEqual([entry["relpath"] for entry in kept], ["a.py", "c.py"])
        self.assertEqual([entry["relpath"] for entry in dropped], ["b.py"])

    def test_the_survivor_is_the_first_in_path_order_not_the_first_listed(self):
        """Same package, same version, same bytes, two member paths.

        The tie has to break on a property of the entries: whichever the
        manifest happened to list first is not a fact about the corpus.
        """
        entries = [{"package": "pkg", "relpath": "z.py", "version": "1", "sha256": "1" * 64},
                   {"package": "pkg", "relpath": "a.py", "version": "1", "sha256": "1" * 64}]
        kept, _ = hc.dedup_by_content(entries)
        self.assertEqual([entry["relpath"] for entry in kept], ["a.py"])

    def test_a_package_under_several_versions_is_not_collapsed(self):
        """The same member path holds different bytes across versions."""
        entries = [{"package": "pkg", "relpath": "core.py", "version": "2", "sha256": "2" * 64},
                   {"package": "pkg", "relpath": "core.py", "version": "1", "sha256": "1" * 64}]
        kept, dropped = hc.dedup_by_content(entries)
        self.assertEqual(len(kept), 2)
        self.assertEqual(dropped, [])

    def test_the_result_does_not_depend_on_the_input_order(self):
        """Otherwise the same manifest read in another order would differ."""
        entries = [{"package": "pkg", "relpath": name, "version": "1", "sha256": "1" * 64}
                   for name in ("m.py", "a.py", "z.py")]
        forward, _ = hc.dedup_by_content(entries)
        backward, _ = hc.dedup_by_content(list(reversed(entries)))
        self.assertEqual([entry["relpath"] for entry in forward],
                         [entry["relpath"] for entry in backward])

    def test_an_entry_with_no_hash_has_nothing_to_dedup_on(self):
        entries = [{"package": "pkg", "relpath": "a.py", "version": "1"},
                   {"package": "pkg", "relpath": "b.py", "version": "1"}]
        kept, dropped = hc.dedup_by_content(entries)
        self.assertEqual(len(kept), 2)
        self.assertEqual(dropped, [])

    def test_the_path_field_is_read_when_there_is_no_relpath(self):
        """Two of the three manifests name the member path `path`."""
        entries = [{"package": "pkg", "path": "b.py", "version": "1", "sha256": "1" * 64},
                   {"package": "pkg", "path": "a.py", "version": "1", "sha256": "1" * 64}]
        kept, _ = hc.dedup_by_content(entries)
        self.assertEqual([entry["path"] for entry in kept], ["a.py"])


class TestDropEmpty(unittest.TestCase):
    """Zero-byte files, split off before anything is read or deduped.

    An empty file holds no code, so it is neither an instance of what an arm
    labels nor a fair negative for one. It is also the file every other empty
    file is byte-identical to, so an arm that deduped first would report the
    rest of them as duplicates of a file that is not a sample.
    """

    def test_it_splits_on_the_size_the_manifest_records(self):
        entries = [dd_entry("a.py", "x = 1\n"), dd_entry("b.py", ""),
                   dd_entry("c.py", "y = 2\n")]
        kept, dropped = hc.drop_empty(entries)

        self.assertEqual([entry["relpath"] for entry in kept], ["a.py", "c.py"])
        self.assertEqual([entry["relpath"] for entry in dropped], ["b.py"])

    def test_nothing_is_read_to_decide(self):
        """The size comes from the manifest, so an entry with no file behind it is
        still dropped as empty - counting it as missing instead would mean the
        size had been read off the disk."""
        with tempfile.TemporaryDirectory() as td:
            empty = dd_entry("b.py", "")
            samples, report = hc.samples_from_malicious(
                [dd_entry("a.py", "x = 1\n"), empty], td, {}
            )

        self.assertEqual(samples, [])
        self.assertEqual(report["empty"], 1)
        self.assertEqual(report["missing_file"], 1)

    def test_it_runs_before_dedup_in_the_malicious_arm(self):
        """Every empty file hashes alike, so an arm that deduped first would call
        the rest of them duplicates of a file that is not a sample."""
        real = "value = 1\n"
        with tempfile.TemporaryDirectory() as td:
            entries = [
                dd_entry("pkg/a.py", real),
                dd_entry("pkg/one.py", "", sha256=hc.sha256_bytes(b"")),
                dd_entry("pkg/two.py", "", sha256=hc.sha256_bytes(b"")),
            ]
            write_file(td, entries[0]["extracted_path"], real)
            samples, report = hc.samples_from_malicious(entries, td, {})

        self.assertEqual([sample.sample_id for sample in samples], ["dd-0001"])
        self.assertEqual(report["empty"], 2)
        self.assertEqual(report["duplicate_content"], 0)

    def test_an_entry_that_records_no_size_is_refused(self):
        """A size read as zero would drop a file that may hold the payload."""
        entry = dd_entry("a.py", "x = 1\n")
        del entry["bytes"]
        with self.assertRaises(ValueError) as caught:
            hc.drop_empty([entry])

        self.assertIn("byte size", str(caught.exception))


class TestCodeQLFileClassification(unittest.TestCase):
    """Four classes, from the annotations a file's own bytes carry."""

    def test_the_class_follows_from_the_annotations_alone(self):
        cases = {
            "negative_only": "a = 1  # $ result=OK\nb = 2  # $ SPURIOUS: Alert\n",
            "positive_only": "a = 1  # $ Alert\nb = 2  # $ Source\n",
            "no_marker": "a = 1\nb = 2  # nothing to see\n",
            "mixed": "a = 1  # $ result=OK\nb = 2  # $ Alert\n",
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                self.assertEqual(hc.codeql_file_class(text, {})["class"], name)

    def test_a_file_needs_a_negative_line_to_be_negative_only(self):
        """An empty file, and a file with no annotation, are not statements."""
        self.assertEqual(hc.codeql_file_class("", {})["class"], "no_marker")
        self.assertEqual(hc.codeql_file_class("a = 1\n", {})["class"], "no_marker")
        verdict = hc.codeql_file_class("a = 1  # $ result=OK\n", {})
        self.assertEqual(verdict["class"], "negative_only")
        self.assertEqual(verdict["negative_lines"], 1)

    def test_a_bare_dollar_is_not_an_annotation_line(self):
        """`re.match(r"^[a-z]+$", s)` has a `$` but no `#` before it."""
        text = 'import re\nif re.match(r"^[a-z]+$", s):\n    pass\n'
        verdict = hc.codeql_file_class(text, {})
        self.assertEqual(verdict["class"], "no_marker")
        self.assertEqual(verdict["annotation_lines"], 0)

    def test_the_two_counts_of_a_mixed_file_are_reported_apart(self):
        text = ("a  # $ result=OK\nb  # $ Alert\nc  # $ Alert\n"
                "d  # $ SPURIOUS: Source\ne = 1\n")
        verdict = hc.codeql_file_class(text, {})

        self.assertEqual(verdict["class"], "mixed")
        self.assertEqual(verdict["negative_lines"], 2)
        self.assertEqual(verdict["positive_lines"], 2)
        self.assertEqual(verdict["annotation_lines"], 4)

    def test_the_per_line_labels_are_the_manifest_map_inverted(self):
        per_line = hc.codeql_per_line_labels({"Alert": [3, 7], "Source": [7]})

        self.assertEqual(per_line, {3: ["Alert"], 7: ["Alert", "Source"]})

    def test_a_line_marking_a_negative_and_an_alert_is_counted(self):
        """`# $ Alert, SPURIOUS: Source` states both at once."""
        label_lines = {"Alert": [1], "SPURIOUS: Source": [1]}
        self.assertEqual(hc.codeql_both_kinds_lines(label_lines), 1)

    def test_one_kind_of_expectation_on_a_line_is_not_both_kinds(self):
        self.assertEqual(hc.codeql_both_kinds_lines({"SPURIOUS: Alert": [1]}), 0)
        self.assertEqual(hc.codeql_both_kinds_lines({"Alert": [1], "Source": [2]}), 0)
        self.assertEqual(hc.codeql_both_kinds_lines({}), 0)
        # Two negatives on one line state one kind of thing twice.
        self.assertEqual(hc.codeql_both_kinds_lines(
            {"SPURIOUS: Alert": [1], "result=OK": [1]}), 0)

    def test_a_malformed_label_map_is_refused(self):
        """It would read as 'no line carries two', which is the answer that keeps
        an ambiguous file in the negative arm."""
        with self.assertRaises(ValueError):
            hc.codeql_both_kinds_lines({"Alert": 1})
        with self.assertRaises(ValueError):
            hc.codeql_both_kinds_lines(None)


class TestCodeQLMarkers(unittest.TestCase):
    """A near-miss is an upstream-written negative, not the absence of a label."""

    def test_an_explicit_marker_is_found_on_a_trailing_comment(self):
        """Upstream writes the marker after the code, not on a line of its own."""
        text = "x = 1  # $ SPURIOUS: Alert\ny = 2  # $ result=OK\n"
        self.assertEqual(hc.codeql_markers(text), {"SPURIOUS": 1, "result=OK": 1})

    def test_a_marker_on_a_comment_line_of_its_own_is_found_too(self):
        """The upstream form is a trailing comment; the comment form is a subset."""
        text = "# $ result=OK\n# $ SPURIOUS: Alert\n"
        self.assertEqual(hc.codeql_markers(text), {"SPURIOUS": 1, "result=OK": 1})

    def test_a_bare_dollar_is_not_a_marker(self):
        """`re.match(r"^[a-z]+$", s)` is an expression with a `$` in it.

        Matching a bare `$` would take every file that anchors a regex as a
        negative, which in this corpus means the alert-positive files too.
        """
        text = 'import re\nif re.match(r"^[a-zA-Z0-9_-]+$", path):\n    pass\n'
        self.assertEqual(hc.codeql_markers(text), {})

    def test_the_marker_has_to_follow_the_dollar(self):
        """`# SPURIOUS` with no `$` is prose, not an annotation."""
        self.assertEqual(hc.codeql_markers("x = 1  # SPURIOUS: Alert\n"), {})

    def test_result_bad_is_not_an_ok_marker(self):
        """`result=BAD` records a wrong result; only `result=OK` is a negative."""
        self.assertEqual(hc.codeql_markers("x = 1  # $ Alert result=BAD\n"), {})

    def test_markers_are_counted_per_line(self):
        text = "a  # $ result=OK\nb  # $ result=OK\nc  # $ SPURIOUS: Alert\n"
        self.assertEqual(hc.codeql_markers(text), {"SPURIOUS": 1, "result=OK": 2})

    def test_the_marker_name_is_canonicalised(self):
        """`result = OK` and `result=OK` are the same upstream marker."""
        self.assertEqual(hc.marker_name("result = OK"), "result=OK")
        self.assertEqual(hc.marker_name(" SPURIOUS "), "SPURIOUS")


class TestCodeQLNearMissSelection(unittest.TestCase):
    def _root(self, tmp, files):
        root = Path(tmp) / hc.CODEQL_DIRNAME
        for relpath, text in files.items():
            write_file(root, relpath, text)
        return root

    def test_only_a_negative_only_file_is_selected(self):
        """The four classes, and the one of them that is a near-miss."""
        files = {
            "CWE-1/neg.py": "a  # $ result=OK\n",
            "CWE-2/pos.py": "a  # $ Alert\n",
            "CWE-3/none.py": "a = 1\n",
            "CWE-4/mixed.py": "a  # $ result=OK\nb  # $ Alert\n",
        }
        with tempfile.TemporaryDirectory() as td:
            root = self._root(td, files)
            entries = [cq_entry(path, text) for path, text in files.items()]
            selected, report = hc.codeql_near_miss_files(entries, root)

        self.assertEqual([entry["path"] for entry in selected], ["CWE-1/neg.py"])
        self.assertEqual(report["classification"],
                         {"negative_only": 1, "positive_only": 1, "no_marker": 1, "mixed": 1})
        self.assertEqual(report["classified"], 4)
        self.assertEqual(report["selected"], 1)

    def test_a_mixed_file_reports_both_of_its_counts(self):
        """The file also asserts that something must be reported, and the report
        says how much of it does."""
        text = "a  # $ result=OK\nb  # $ Alert\nc  # $ Source\n"
        with tempfile.TemporaryDirectory() as td:
            root = self._root(td, {"CWE-4/mixed.py": text})
            _, report = hc.codeql_near_miss_files([cq_entry("CWE-4/mixed.py", text)], root)

        self.assertEqual(report["mixed_files"], [
            {"path": "CWE-4/mixed.py", "negative_lines": 1, "positive_lines": 2},
        ])
        self.assertEqual(report["selected"], 0)

    def test_a_line_marking_a_negative_and_an_alert_at_once_excludes_the_file(self):
        """`# $ Alert, SPURIOUS: Source` reads as a negative line under the line
        rule while it also asks for an alert, so the file is left out."""
        text = "a  # $ Alert, SPURIOUS: Source\nb  # $ result=OK\n"
        labels = {"Alert": [1], "SPURIOUS: Source": [1], "result=OK": [2]}
        with tempfile.TemporaryDirectory() as td:
            root = self._root(td, {"CWE-4/both.py": text})
            entries = [cq_entry("CWE-4/both.py", text, label_lines=labels)]
            selected, report = hc.codeql_near_miss_files(entries, root)

        self.assertEqual(selected, [])
        # Every annotation line is negative, so the line rule alone would keep it.
        self.assertEqual(report["classification"]["negative_only"], 1)
        self.assertEqual(report["both_kinds_lines"], 1)
        self.assertEqual(report["both_kinds_files"], ["CWE-4/both.py"])
        self.assertEqual(report["excluded_both_kinds"], 1)
        self.assertEqual(report["selected"], 0)

    def test_a_line_stating_one_kind_of_expectation_does_not_exclude_the_file(self):
        """Two negatives on one line are one kind of statement, not two."""
        text = "a  # $ SPURIOUS: Alert, result=OK\n"
        labels = {"SPURIOUS: Alert": [1], "result=OK": [1]}
        with tempfile.TemporaryDirectory() as td:
            root = self._root(td, {"CWE-4/neg.py": text})
            entries = [cq_entry("CWE-4/neg.py", text, label_lines=labels)]
            selected, report = hc.codeql_near_miss_files(entries, root)

        self.assertEqual([entry["path"] for entry in selected], ["CWE-4/neg.py"])
        self.assertEqual(report["both_kinds_lines"], 0)
        self.assertEqual(report["excluded_both_kinds"], 0)

    def test_a_zero_byte_file_is_dropped_before_it_is_read(self):
        """No such file on disk: a read would be counted as missing instead."""
        with tempfile.TemporaryDirectory() as td:
            root = self._root(td, {})
            entries = [cq_entry("CWE-1/gone.py", "", bytes=0)]
            selected, report = hc.codeql_near_miss_files(entries, root)

        self.assertEqual(selected, [])
        self.assertEqual(report["empty"], 1)
        self.assertEqual(report["classified"], 0)

    def test_a_file_with_a_marker_is_selected_and_one_without_is_not(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._root(td, {
                "CWE-001/x.py": "x = 1  # $ result=OK\n",
                "CWE-002/y.py": "y = 2  # $ Alert\n",
            })
            entries = [
                cq_entry("CWE-001/x.py", "x = 1  # $ result=OK\n", labels=["result=OK"]),
                cq_entry("CWE-002/y.py", "y = 2  # $ Alert\n", labels=["Alert"]),
            ]
            selected, report = hc.codeql_near_miss_files(entries, root)

        self.assertEqual([entry["path"] for entry in selected], ["CWE-001/x.py"])
        self.assertEqual(report["total_entries"], 2)
        self.assertEqual(report["selected"], 1)

    def test_an_alert_positive_file_is_not_a_near_miss(self):
        """67 of the 102 real files carry annotations and none of them negative.
        Upstream says a query SHOULD fire on those, and counting them as
        negatives would score an engine's correct alerts as false positives."""
        with tempfile.TemporaryDirectory() as td:
            root = self._root(td, {"CWE-003/z.py": "z = 3  # $ Alert\n"})
            entries = [cq_entry("CWE-003/z.py", "z = 3  # $ Alert\n", labels=["Alert"])]
            selected, report = hc.codeql_near_miss_files(entries, root)

        self.assertEqual(selected, [])
        self.assertEqual(report["alert_positive_only"], 1)
        self.assertEqual(report["classification"]["positive_only"], 1)

    def test_the_report_tallies_markers_by_name_and_by_file(self):
        with tempfile.TemporaryDirectory() as td:
            files = {
                "a.py": "a  # $ result=OK\nb  # $ result=OK\n",
                "b.py": "c  # $ SPURIOUS: Alert\n",
            }
            root = self._root(td, files)
            entries = [cq_entry("a.py", files["a.py"], labels=["result=OK"]),
                       cq_entry("b.py", files["b.py"], labels=["SPURIOUS: Alert"])]
            _, report = hc.codeql_near_miss_files(entries, root)

        self.assertEqual(report["marker_tallies"], {"SPURIOUS": 1, "result=OK": 2})
        self.assertEqual(report["marker_files"], {"SPURIOUS": 1, "result=OK": 1})

    def test_the_manifest_labels_are_read_as_a_second_opinion(self):
        """The file's bytes decide, and the manifest's `labels` has to agree.

        Measured on the real manifest the two agree on all 102 entries; this
        pins the check that would notice if they stopped.
        """
        with tempfile.TemporaryDirectory() as td:
            root = self._root(td, {"a.py": "a = 1\n", "b.py": "b  # $ result=OK\n"})
            entries = [cq_entry("a.py", "a = 1\n", labels=["result=OK"]),
                       cq_entry("b.py", "b  # $ result=OK\n", labels=["Alert"])]
            selected, report = hc.codeql_near_miss_files(entries, root)

        self.assertEqual([entry["path"] for entry in selected], ["b.py"])
        self.assertEqual(report["label_marked"], 1)
        self.assertEqual(report["file_marked"], 1)
        self.assertEqual(report["label_and_file_disagree"], 2)

    def test_a_file_whose_bytes_are_not_the_manifest_s_is_refused(self):
        """The marker would otherwise be read out of a file nobody described."""
        with tempfile.TemporaryDirectory() as td:
            root = self._root(td, {"a.py": "a = 1  # $ result=OK\n"})
            entries = [cq_entry("a.py", "a = 1  # $ result=OK\n", sha256="b" * 64)]
            with self.assertRaises(ValueError) as caught:
                hc.codeql_near_miss_files(entries, root)

        self.assertIn("sha256", str(caught.exception))

    def test_a_listed_file_that_is_not_there_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._root(td, {})
            with self.assertRaises(ValueError):
                hc.codeql_near_miss_files([cq_entry("gone.py", "x\n")], root)


class TestSamplesFromMalicious(unittest.TestCase):
    """The malicious arm: a label per file, with every exclusion counted."""

    def _load(self, tmp, entries, reference=None, files=None):
        root = Path(tmp)
        for relpath, payload in (files or {}).items():
            write_file(root, relpath, payload)
        return hc.samples_from_malicious(entries, root, reference or {})

    def test_a_non_vendored_file_becomes_a_malicious_sample(self):
        text = "import os\n\nos.system(input())\n"
        with tempfile.TemporaryDirectory() as td:
            entry = dd_entry("pkg/dt.py", text)
            samples, report = self._load(td, [entry], files={entry["extracted_path"]: text})

        self.assertEqual(len(samples), 1)
        sample = samples[0]
        self.assertEqual(sample.sample_id, "dd-0001")
        self.assertEqual(sample.base_project, "ddpypi")
        self.assertEqual(sample.label, "malicious")
        self.assertEqual(sample.text, text)
        self.assertEqual(sample.family, hc.FAMILY_DATADOG)
        self.assertIsNone(sample.primary_attack_finding)
        self.assertEqual(report["loaded"], 1)
        self.assertEqual(report["family_unmapped"], 1)

    def test_provenance_carries_the_upstream_coordinates_and_why_it_is_malicious(self):
        """The label is checkable only against the fact that produced it."""
        text = "value = 1\n"
        with tempfile.TemporaryDirectory() as td:
            entry = dd_entry("pkg/mod.py", text)
            samples, _ = self._load(td, [entry], files={entry["extracted_path"]: text})

        source = samples[0].provenance
        self.assertEqual(source["source"], hc.MALICIOUS_SOURCE)
        self.assertEqual(source["package"], "pkg")
        self.assertEqual(source["version"], "1.0.0")
        self.assertEqual(source["archive_sha256"], HEX64)
        self.assertEqual(source["in_archive_path"], entry["in_archive_path"])
        self.assertEqual(source["file_sha256"], hc.sha256_text(text))
        self.assertEqual(source["label_basis"], hc.MALICIOUS_LABEL_BASIS)

    def test_a_path_naming_a_family_gets_that_family_and_a_finding(self):
        """The member path is upstream-ish evidence, and nothing else is read.

        The engine is deliberately not consulted: a holdout judged by the engine
        under test is not held out.
        """
        text = "import subprocess\n"
        with tempfile.TemporaryDirectory() as td:
            entry = dd_entry("pkg/subprocess_runner.py", text)
            samples, report = self._load(td, [entry], files={entry["extracted_path"]: text})

        self.assertEqual(samples[0].family, "CMD_001")
        self.assertEqual(samples[0].primary_attack_finding,
                         {"file": hc.SAMPLE_FILENAME, "rule_id": "CMD_001", "line": 1})
        self.assertEqual(report["family_mapped"], 1)
        self.assertEqual(report["family_unmapped"], 0)

    def test_a_vendored_file_is_dropped_before_it_is_read(self):
        """It is somebody else's released library, not this package's payload."""
        text = "value = 1\n"
        entry = dd_entry("pkg/mod.py", text)
        reference = {hc.sha256_text(text): "attrs==26.1.0"}
        with tempfile.TemporaryDirectory() as td:
            # No file on disk: the drop happens before anything is opened, so a
            # vendored entry with nothing behind it must not reach the reader.
            samples, report = self._load(td, [entry], reference=reference)

        self.assertEqual(samples, [])
        self.assertEqual(report["vendored"], 1)
        self.assertEqual(report["loaded"], 0)

    def test_duplicate_content_is_dropped_and_counted(self):
        text = "value = 1\n"
        with tempfile.TemporaryDirectory() as td:
            first = dd_entry("pkg/a.py", text)
            second = dd_entry("pkg/b.py", text, extracted_path="dd/extracted/pkg/1.0.0/pkg/b.py")
            samples, report = self._load(td, [first, second], files={
                first["extracted_path"]: text,
                second["extracted_path"]: text,
            })

        self.assertEqual(len(samples), 1)
        self.assertEqual(report["duplicate_content"], 1)

    def test_a_directory_named_py_is_dropped_and_counted(self):
        """Some archive members are directories literally named `*.py`."""
        entry = dd_entry("pkg/dir.py", "value = 1\n")
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / entry["extracted_path"]).mkdir(parents=True)
            samples, report = self._load(td, [entry])

        self.assertEqual(samples, [])
        self.assertEqual(report["directory_entry"], 1)

    def test_a_path_the_retrieval_never_produced_is_dropped_and_counted(self):
        """An absent path means the manifest and the extraction disagree."""
        entry = dd_entry("pkg/gone.py", "value = 1\n")
        with tempfile.TemporaryDirectory() as td:
            samples, report = self._load(td, [entry])

        self.assertEqual(samples, [])
        self.assertEqual(report["missing_file"], 1)

    def test_a_file_that_is_not_utf8_is_excluded_not_read_as_text(self):
        """The evaluator reads a sample as text, so an undecodable one cannot run."""
        payload = b"\xff\xfevalue = 1\n"
        entry = dd_entry("pkg/binary.py", "value = 1\n", sha256=hc.sha256_bytes(payload))
        with tempfile.TemporaryDirectory() as td:
            samples, report = self._load(
                td, [entry], files={entry["extracted_path"]: payload}
            )

        self.assertEqual(samples, [])
        self.assertEqual(report["undecodable"], 1)

    def test_an_empty_file_is_excluded_and_counted(self):
        """An empty sample scores as a file with nothing in it, not as malware."""
        entry = dd_entry("pkg/empty.py", "")
        with tempfile.TemporaryDirectory() as td:
            samples, report = self._load(td, [entry], files={entry["extracted_path"]: ""})

        self.assertEqual(samples, [])
        self.assertEqual(report["empty"], 1)

    def test_a_whitespace_only_file_is_the_same_drop(self):
        """Its bytes are there and hold nothing to score, which is counted as the
        same exclusion rather than admitted as a sample with no text."""
        payload = "  \n\n\t\n"
        entry = dd_entry("pkg/blank.py", payload)
        with tempfile.TemporaryDirectory() as td:
            samples, report = self._load(
                td, [entry], files={entry["extracted_path"]: payload}
            )

        self.assertEqual(samples, [])
        self.assertEqual(report["empty"], 1)
        self.assertEqual(report["undecodable"], 0)

    def test_a_file_that_does_not_hash_to_the_manifest_is_refused(self):
        entry = dd_entry("pkg/mod.py", "value = 1\n", sha256="c" * 64)
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError) as caught:
                self._load(td, [entry], files={entry["extracted_path"]: "value = 1\n"})

        self.assertIn("sha256", str(caught.exception))

    def test_every_drop_reason_is_reported_even_at_zero(self):
        """A missing key reads as 'no drops', which a clean build cannot prove."""
        text = "value = 1\n"
        with tempfile.TemporaryDirectory() as td:
            entry = dd_entry("pkg/mod.py", text)
            _, report = self._load(td, [entry], files={entry["extracted_path"]: text})

        self.assertEqual(set(report), set(hc.MALICIOUS_DROP_KEYS))
        # The family counters are not drops: one of the two is always non-zero
        # for a file that loaded.
        for key in hc.MALICIOUS_DROP_KEYS:
            if key not in ("entries", "loaded", "family_mapped", "family_unmapped"):
                with self.subTest(key=key):
                    self.assertEqual(report[key], 0)


class TestSamplesFromBenign(unittest.TestCase):
    """The sdist arm: a member of a published archive, read from the archive."""

    def _sources(self, tmp, members, entries):
        root = Path(tmp)
        archive = make_sdist(root / hc.SDIST_DIRNAME / "attrs-26.1.0.tar.gz", members)
        payload = archive.read_bytes()
        return root, [sdist_entry(member, "attrs-26.1.0.tar.gz", payload, text)
                      for member, text in entries]

    def test_a_member_becomes_a_benign_sample(self):
        text = "def f():\n    return 1\n"
        with tempfile.TemporaryDirectory() as td:
            root, entries = self._sources(
                td, {"attrs-26.1.0/src/attr/_make.py": text.encode()},
                [("attrs-26.1.0/src/attr/_make.py", text)],
            )
            samples, report = hc.samples_from_benign(entries, root)

        self.assertEqual(len(samples), 1)
        sample = samples[0]
        self.assertEqual(sample.sample_id, "pypi-0001")
        self.assertEqual(sample.base_project, "pypi")
        self.assertEqual(sample.family, hc.FAMILY_PYPI)
        self.assertEqual(sample.label, "benign")
        self.assertIsNone(sample.primary_attack_finding)
        self.assertEqual(report["loaded"], 1)

    def test_provenance_names_the_archive_the_member_came_out_of(self):
        text = "value = 1\n"
        with tempfile.TemporaryDirectory() as td:
            root, entries = self._sources(
                td, {"attrs-26.1.0/a.py": text.encode()}, [("attrs-26.1.0/a.py", text)]
            )
            samples, _ = hc.samples_from_benign(entries, root)

        source = samples[0].provenance
        self.assertEqual(source["source"], hc.SDIST_SOURCE)
        self.assertEqual(source["archive_filename"], "attrs-26.1.0.tar.gz")
        self.assertEqual(source["in_archive_path"], "attrs-26.1.0/a.py")
        self.assertEqual(source["file_sha256"], hc.sha256_text(text))
        self.assertEqual(source["label_basis"], hc.SDIST_LABEL_BASIS)

    def test_an_archive_that_is_not_on_disk_is_dropped_and_counted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            entry = sdist_entry("attrs-26.1.0/a.py", "attrs-26.1.0.tar.gz", b"", "value = 1\n")
            samples, report = hc.samples_from_benign([entry], root)

        self.assertEqual(samples, [])
        self.assertEqual(report["missing_archive"], 1)

    def test_a_member_the_archive_does_not_hold_is_dropped_and_counted(self):
        with tempfile.TemporaryDirectory() as td:
            root, _ = self._sources(td, {"attrs-26.1.0/a.py": b"x = 1\n"}, [])
            entry = sdist_entry("attrs-26.1.0/absent.py", "attrs-26.1.0.tar.gz",
                                (root / hc.SDIST_DIRNAME / "attrs-26.1.0.tar.gz").read_bytes(),
                                "value = 1\n")
            samples, report = hc.samples_from_benign([entry], root)

        self.assertEqual(samples, [])
        self.assertEqual(report["missing_member"], 1)

    def test_an_archive_whose_bytes_are_not_the_manifest_s_is_refused(self):
        """A sample's provenance claims a download, and that claim is checked."""
        text = "value = 1\n"
        with tempfile.TemporaryDirectory() as td:
            root, entries = self._sources(
                td, {"attrs-26.1.0/a.py": text.encode()}, [("attrs-26.1.0/a.py", text)]
            )
            entries[0]["archive_sha256_observed"] = "d" * 64
            with self.assertRaises(ValueError) as caught:
                hc.samples_from_benign(entries, root)

        self.assertIn("archive", str(caught.exception))

    def test_a_zero_byte_member_is_dropped_before_the_archive_is_opened(self):
        """No archive on disk: a build that read first would count this member as
        missing rather than as empty."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            entry = sdist_entry("attrs-26.1.0/a.py", "attrs-26.1.0.tar.gz", b"", "")
            samples, report = hc.samples_from_benign([entry], root)

        self.assertEqual(samples, [])
        self.assertEqual(report["empty"], 1)
        self.assertEqual(report["missing_archive"], 0)

    def test_a_member_that_is_not_utf8_is_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            root, entries = self._sources(
                td, {"attrs-26.1.0/a.py": b"\xff\xfex = 1\n"}, [("attrs-26.1.0/a.py", "value = 1\n")]
            )
            entries[0]["sha256"] = hc.sha256_bytes(b"\xff\xfex = 1\n")
            samples, report = hc.samples_from_benign(entries, root)

        self.assertEqual(samples, [])
        self.assertEqual(report["undecodable"], 1)

    def test_every_drop_reason_is_reported_even_at_zero(self):
        text = "value = 1\n"
        with tempfile.TemporaryDirectory() as td:
            root, entries = self._sources(
                td, {"attrs-26.1.0/a.py": text.encode()}, [("attrs-26.1.0/a.py", text)]
            )
            _, report = hc.samples_from_benign(entries, root)

        self.assertEqual(set(report), set(hc.SDIST_DROP_KEYS))
        for key in hc.SDIST_DROP_KEYS:
            if key not in ("entries", "loaded"):
                with self.subTest(key=key):
                    self.assertEqual(report[key], 0)


class TestSamplesFromNearMiss(unittest.TestCase):
    def test_a_selected_file_becomes_a_benign_sample_with_no_finding(self):
        """The marker says a query must not fire, which is a negative verdict."""
        text = "x = 1  # $ result=OK\n"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write_file(root, f"{hc.CODEQL_DIRNAME}/a.py", text)
            entry = cq_entry("a.py", text, labels=["result=OK"])
            samples, report = hc.samples_from_near_miss([entry], root)

        self.assertEqual(len(samples), 1)
        sample = samples[0]
        self.assertEqual(sample.sample_id, "cq-0001")
        self.assertEqual(sample.base_project, "codeql")
        self.assertEqual(sample.family, hc.FAMILY_CODEQL)
        self.assertEqual(sample.label, "benign")
        self.assertIsNone(sample.primary_attack_finding)
        self.assertEqual(sample.provenance["label_basis"], hc.CODEQL_LABEL_BASIS)
        self.assertEqual(report["loaded"], 1)

    def test_this_arm_has_no_archive_to_name(self):
        """The upstream coordinate is a git blob at a commit, not a download."""
        text = "x = 1  # $ result=OK\n"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write_file(root, f"{hc.CODEQL_DIRNAME}/a.py", text)
            samples, _ = hc.samples_from_near_miss([cq_entry("a.py", text)], root)

        self.assertIsNone(samples[0].provenance["archive_sha256"])
        self.assertEqual(samples[0].provenance["git_blob_sha1"], "0" * 40)

    def test_a_file_that_is_not_there_is_dropped_and_counted(self):
        with tempfile.TemporaryDirectory() as td:
            samples, report = hc.samples_from_near_miss([cq_entry("gone.py", "x\n")], td)

        self.assertEqual(samples, [])
        self.assertEqual(report["missing_file"], 1)

    def test_a_zero_byte_file_is_dropped_before_it_is_read(self):
        with tempfile.TemporaryDirectory() as td:
            entry = cq_entry("gone.py", "", bytes=0)
            samples, report = hc.samples_from_near_miss([entry], td)

        self.assertEqual(samples, [])
        self.assertEqual(report["empty"], 1)
        self.assertEqual(report["missing_file"], 0)

    def test_every_drop_reason_is_reported_even_at_zero(self):
        text = "x = 1  # $ result=OK\n"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write_file(root, f"{hc.CODEQL_DIRNAME}/a.py", text)
            _, report = hc.samples_from_near_miss([cq_entry("a.py", text)], root)

        self.assertEqual(set(report), set(hc.CODEQL_DROP_KEYS))
        for key in hc.CODEQL_DROP_KEYS:
            if key not in ("entries", "loaded"):
                with self.subTest(key=key):
                    self.assertEqual(report[key], 0)


class TestBuildHoldout(unittest.TestCase):
    """The three manifest-backed arms, in one fixed order, with one report.

    The whole build is exercised against a synthetic source tree: real malware
    bytes appear nowhere in a test, and the shapes the build reads - a
    reference, two manifests, an sdist directory and a CodeQL directory - are
    the parts that can be wrong.
    """

    MALICIOUS_FILES = {
        "dd/extracted/pkg/1.0.0/pkg/subprocess_runner.py": "import subprocess\n",
        "dd/extracted/pkg/1.0.0/setup.py": "import setuptools\n",
        "dd/extracted/pkg/1.0.0/pkg/released.py": "value = 1\n",
        "dd/extracted/pkg/1.0.0/pkg/empty.py": "",
    }
    SDIST_MEMBERS = {"attrs-26.1.0/src/attr/_make.py": b"def f():\n    return 1\n"}
    CODEQL_FILES = {
        "CWE-001/x.py": "x = 1  # $ result=OK\n",
        "CWE-002/y.py": "y = 2  # $ Alert\n",
        "CWE-003/empty.py": "",
    }

    def _sources(self, tmp):
        root = Path(tmp)
        for relpath, text in self.MALICIOUS_FILES.items():
            write_file(root, relpath, text)
        archive = make_sdist(root / hc.SDIST_DIRNAME / "attrs-26.1.0.tar.gz", self.SDIST_MEMBERS)
        for relpath, text in self.CODEQL_FILES.items():
            write_file(root / hc.CODEQL_DIRNAME, relpath, text)

        released = self.MALICIOUS_FILES["dd/extracted/pkg/1.0.0/pkg/released.py"]
        write_reference(root, [
            {"dist": "attrs", "version": "26.1.0", "url": "https://example.invalid/attrs",
             "sdist_sha256": hc.sha256_bytes(archive.read_bytes()),
             "file_sha256": [hc.sha256_text(released)], "matched_entries": 1},
        ])
        write_file(root, hc.MALICIOUS_MANIFEST_FILENAME, json.dumps({
            "retrieved_at": "2026-09-24",
            "source": "DataDog/malicious-software-packages-dataset",
            "revision": "0" * 40,
            "category": "samples/pypi/malicious_intent",
            "entries": [
                dd_entry("pkg/subprocess_runner.py",
                         self.MALICIOUS_FILES["dd/extracted/pkg/1.0.0/pkg/subprocess_runner.py"]),
                dd_entry("setup.py", self.MALICIOUS_FILES["dd/extracted/pkg/1.0.0/setup.py"]),
                dd_entry("pkg/released.py", released),
                dd_entry("pkg/empty.py", ""),
            ],
        }))
        write_file(root, hc.BENIGN_MANIFEST_FILENAME, json.dumps({
            "retrieved_at": "2026-09-24",
            "semgrep_version": "1.177.0",
            "codeql": {"repo": "github/codeql", "ref": "0" * 40, "subtree": "python/ql/test"},
            "entries": [
                sdist_entry("attrs-26.1.0/src/attr/_make.py", "attrs-26.1.0.tar.gz",
                            archive.read_bytes(), self.SDIST_MEMBERS[
                                "attrs-26.1.0/src/attr/_make.py"].decode()),
                cq_entry("CWE-001/x.py", self.CODEQL_FILES["CWE-001/x.py"], labels=["result=OK"]),
                cq_entry("CWE-002/y.py", self.CODEQL_FILES["CWE-002/y.py"], labels=["Alert"]),
                cq_entry("CWE-003/empty.py", "", bytes=0),
            ],
        }))
        return root

    def test_it_builds_the_three_arms_in_a_fixed_order(self):
        with tempfile.TemporaryDirectory() as td:
            samples, report = hc.build_holdout(self._sources(td))

        self.assertEqual([sample.sample_id for sample in samples],
                         ["dd-0001", "dd-0002", "pypi-0001", "cq-0001"])
        self.assertEqual([sample.label for sample in samples],
                         ["malicious", "malicious", "benign", "benign"])
        self.assertEqual(report["total"], 4)
        self.assertEqual(report["counts"]["by_source"],
                         {hc.MALICIOUS_SOURCE: 2, hc.SDIST_SOURCE: 1, hc.CODEQL_SOURCE: 1})

    def test_the_report_states_every_arm_and_its_drops(self):
        with tempfile.TemporaryDirectory() as td:
            _, report = hc.build_holdout(self._sources(td))

        malicious = report["arms"][hc.MALICIOUS_SOURCE]
        self.assertEqual(malicious["entries"], 4)
        self.assertEqual(malicious["empty"], 1)
        self.assertEqual(malicious["vendored"], 1)
        self.assertEqual(malicious["loaded"], 2)
        self.assertEqual(malicious["family_mapped"], 1)
        self.assertEqual(malicious["family_unmapped"], 1)
        self.assertEqual(report["arms"][hc.CODEQL_SOURCE]["selection"]["selected"], 1)
        self.assertEqual(report["arms"][hc.SDIST_SOURCE]["loaded"], 1)

    def test_the_codeql_arm_counts_the_empties_the_selection_dropped(self):
        """The arm's population is everything the retrieval downloaded, and the
        zero-byte files among them are dropped at selection; the loader never
        sees one, so the arm reports the selection's count and not zero."""
        with tempfile.TemporaryDirectory() as td:
            _, report = hc.build_holdout(self._sources(td))

        arm = report["arms"][hc.CODEQL_SOURCE]
        self.assertEqual(arm["entries"], 3)
        self.assertEqual(arm["empty"], 1)
        self.assertEqual(arm["selection"]["empty"], 1)
        self.assertEqual(arm["selection"]["classified"], 2)
        self.assertEqual(arm["selection"]["classification"],
                         {"negative_only": 1, "positive_only": 1, "no_marker": 0, "mixed": 0})
        self.assertEqual(arm["loaded"], 1)

    def test_the_malicious_arm_is_split_by_family_not_by_the_engine(self):
        """The mapped file is the one whose path names a family, nothing else."""
        with tempfile.TemporaryDirectory() as td:
            samples, _ = hc.build_holdout(self._sources(td))

        scored = [sample for sample in samples if sample.family == "CMD_001"]
        self.assertEqual([sample.sample_id for sample in scored], ["dd-0001"])
        self.assertEqual(scored[0].primary_attack_finding["rule_id"], "CMD_001")
        self.assertTrue(all(sample.primary_attack_finding is None
                            for sample in samples if sample.family != "CMD_001"))

    def test_the_sources_record_the_manifests_the_build_read(self):
        with tempfile.TemporaryDirectory() as td:
            _, report = hc.build_holdout(self._sources(td))

        names = [source["name"] for source in report["sources"]]
        self.assertEqual(names, [hc.MALICIOUS_SOURCE, hc.SDIST_SOURCE, hc.CODEQL_SOURCE])
        self.assertEqual(report["sources"][0]["revision"], "0" * 40)
        self.assertEqual(report["sources"][1]["semgrep_version"], "1.177.0")
        self.assertEqual(report["sources"][2]["repo"], "github/codeql")

    def test_an_arm_this_build_does_not_know_is_refused(self):
        """Ignoring it would build a corpus smaller than the retrieval produced."""
        with tempfile.TemporaryDirectory() as td:
            root = self._sources(td)
            payload = json.loads((root / hc.BENIGN_MANIFEST_FILENAME).read_text())
            payload["entries"].append(dict(payload["entries"][0], arm="third-arm"))
            write_file(root, hc.BENIGN_MANIFEST_FILENAME, json.dumps(payload))
            with self.assertRaises(ValueError) as caught:
                hc.build_holdout(root)

        self.assertIn("third-arm", str(caught.exception))

    def test_the_built_corpus_is_accepted_by_the_evaluator(self):
        """The contract is the evaluator's, so the evaluator is what checks it.

        Reading its loader and copying the field list is not the same as the
        loader accepting a corpus this build wrote.
        """
        with tempfile.TemporaryDirectory() as td:
            samples, _ = hc.build_holdout(self._sources(td))
            out = Path(td) / "corpus"
            counts = hc.write_corpus(out, samples)
            specs = ev.load_corpus_list(out / "corpus-list.json")

        self.assertEqual([spec.sample_id for spec in specs],
                         ["dd-0001", "dd-0002", "pypi-0001", "cq-0001"])
        self.assertEqual([spec.label for spec in specs],
                         ["malicious", "malicious", "benign", "benign"])
        self.assertEqual(specs[0].relative_path, "ddpypi/dd-0001")
        self.assertEqual(counts["total"], 4)
        self.assertEqual(counts["by_label"], {"malicious": 2, "benign": 2})
        self.assertEqual(counts["by_family"]["CMD_001"], {"malicious": 1})

    def test_the_manifest_loader_reads_the_entries_and_names_its_arm(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._sources(td)
            payload = hc.load_manifest(root / hc.BENIGN_MANIFEST_FILENAME)

        self.assertEqual(len(payload["entries"]), 4)
        self.assertEqual(len(hc.manifest_entries(payload, hc.BENIGN_ARM)), 1)
        self.assertEqual(len(hc.manifest_entries(payload, hc.NEAR_MISS_ARM)), 3)
        with self.assertRaises(ValueError):
            hc.manifest_entries(payload)

    def test_a_manifest_without_an_entries_list_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = write_file(td, hc.MALICIOUS_MANIFEST_FILENAME, json.dumps({"files": []}))
            with self.assertRaises(ValueError) as caught:
                hc.load_manifest(path)

        self.assertIn("entries", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
