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
import unittest

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


if __name__ == "__main__":
    unittest.main()
