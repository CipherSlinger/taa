# tests/test_analyzer_prompt_seam.py
"""The prompt an engine comparison reasons about must be the prompt that was sent.

Spec section 9.2 requirement 8 asks for per-sample prompt equivalence between the
two engines. Prompts were built inline and consumed in the same expression, so
the only way to observe one was to reproduce the construction somewhere else -
and a reproduction is a different object from the thing being compared. If it
drifts, the comparison keeps passing while reporting on text nobody sent.

Splitting construction into a named step makes the string observable without
becoming a second implementation: the sender and the observer call the same
function.
"""
import tempfile
import unittest
from pathlib import Path

from models.examples.code_security_analyzer import Finding, LLMSecurityAnalyzer


def make_finding(**overrides) -> Finding:
    base = dict(
        file="train.py", line=3, rule_id="CMD_001", category="execution",
        severity="HIGH", description="shell command", code_snippet="os.system(cmd)",
        context_before="ctx before\n", context_after="ctx after\n", engine="semgrep",
    )
    base.update(overrides)
    return Finding(**base)


class RecordingAnalyzer(LLMSecurityAnalyzer):
    """An analyzer whose backend records the prompt instead of sending it."""

    def __init__(self):
        super().__init__(model_name="stub", backend="ollama", llm_seed=1)
        self.sent = []

    def _call_ollama(self, prompt, num_predict=200):
        self.sent.append(prompt)
        return {"verdict": "BENIGN", "reason": "", "risk": "",
                "risk_level": "LOW", "summary": "", "chained": False, "exfiltration": False}


class TestFindingPromptSeam(unittest.TestCase):
    def test_the_prompt_sent_for_a_finding_is_the_one_that_was_built(self):
        for name, overrides in (
            ("plain", {}),
            ("cpg evidence", {"cpg_evidence": "CPG: taint path a -> b"}),
            ("ast scope", {"ast_enclosing_block": "def f():\n    os.system(cmd)"}),
            ("snippet only", {"context_before": "", "context_after": ""}),
        ):
            with self.subTest(shape=name):
                analyzer = RecordingAnalyzer()
                finding = make_finding(**overrides)
                expected = analyzer.build_finding_prompt(finding)

                analyzer.analyze_finding(finding)

                self.assertEqual(analyzer.sent, [expected])

    def test_the_slots_are_the_values_the_template_was_rendered_from(self):
        """The slots are for attributing a difference, so they must be the real inputs."""
        analyzer = RecordingAnalyzer()
        finding = make_finding(cpg_evidence="CPG: taint path a -> b")
        slots = analyzer.finding_prompt_slots(finding)

        prompt = analyzer.build_finding_prompt(finding)
        self.assertIn(slots["code_snippet"], prompt)
        self.assertIn(slots["context_after"], prompt)
        self.assertEqual(slots["rule_id"], "CMD_001")
        self.assertEqual(slots["file"], "train.py")
        self.assertIn("第 3 行", prompt)

    def test_cpg_evidence_replaces_the_trailing_context(self):
        analyzer = RecordingAnalyzer()
        finding = make_finding(cpg_evidence="CPG: taint path a -> b")
        slots = analyzer.finding_prompt_slots(finding)
        self.assertEqual(slots["context_after"], "CPG: taint path a -> b")

    def test_an_ast_scope_changes_the_prompt_for_the_same_hit(self):
        """The two engines describe the same hit differently, and that is live today.

        The regex adapter fills context_before/context_after; the semgrep adapter
        fills ast_enclosing_block instead. Same file, same rule, same line, and
        the model is asked two different questions - so a difference in verdicts
        between the arms is not attributable to the engine alone. This test pins
        the mechanism that requirement 8 exists to catch.
        """
        analyzer = RecordingAnalyzer()
        regex_style = make_finding(context_before="before\n", context_after="after\n")
        semgrep_style = make_finding(
            context_before="", context_after="",
            ast_enclosing_block="def f():\n    os.system(cmd)\n",
        )

        self.assertNotEqual(
            analyzer.build_finding_prompt(regex_style),
            analyzer.build_finding_prompt(semgrep_style),
        )


class TestFilePromptSeam(unittest.TestCase):
    def _write(self, root: Path, text: str) -> Path:
        path = root / "train.py"
        path.write_text(text, encoding="utf-8")
        return path

    def test_the_prompt_sent_for_a_file_is_the_one_that_was_built(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(Path(td), "import os\nos.system(cmd)\n")
            analyzer = RecordingAnalyzer()
            expected = analyzer.build_file_prompt(str(path), [make_finding()])

            analyzer.analyze_file(str(path), [make_finding()])

        self.assertEqual(analyzer.sent, [expected])

    def test_a_file_over_the_line_budget_still_agrees(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(Path(td), "\n".join(f"line{i}" for i in range(60)))
            analyzer = RecordingAnalyzer()
            finding = make_finding(line=30)
            expected = analyzer.build_file_prompt(str(path), [finding], max_lines=10)

            analyzer.analyze_file(str(path), [finding], max_lines=10)

        self.assertEqual(analyzer.sent, [expected])

    def test_an_unreadable_file_has_no_prompt_and_keeps_its_verdict(self):
        analyzer = RecordingAnalyzer()
        missing = "/nonexistent/definitely/not/here.py"

        self.assertIsNone(analyzer.build_file_prompt(missing, [make_finding()]))

        summary = analyzer.analyze_file(missing, [make_finding()])
        self.assertEqual(summary.risk_level, "UNCERTAIN")
        self.assertEqual(analyzer.sent, [])


if __name__ == "__main__":
    unittest.main()
