# tests/test_llm_seed.py
"""The LLM sampling seed must be fixed, configurable and recorded.

The paired design compares three regex runs against three Semgrep runs and
requires non-inferiority on *every* pair (spec 5.3). Without a fixed seed the
sampling noise of the model is folded into that comparison, so a difference
between arms can be produced by sampling rather than by the engine. Pinning the
seed makes each pair close to deterministic and separates the two.

The temperature is deliberately left at 0.1: changing it would change the
treatment being measured rather than the measurement.
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from models.audit.tools import audit_benchmark_eval as ev
from models.examples.code_security_analyzer import LLMSecurityAnalyzer, parse_args


def _capture_ollama_payload(analyzer, prompt="analyse this"):
    """Run _call_ollama against a stubbed HTTP layer and return the JSON body."""
    response = MagicMock()
    response.read.return_value = json.dumps(
        {"response": '{"verdict":"BENIGN","reason":"ok","risk":""}'}
    ).encode()
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["body"] = json.loads(request.data.decode())
        return response

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        analyzer._call_ollama(prompt)
    return captured["body"]


class TestOllamaSeed(unittest.TestCase):
    def test_default_seed_is_sent_and_temperature_is_untouched(self):
        analyzer = LLMSecurityAnalyzer(model_name="qwen2.5-coder:3b", backend="ollama")
        payload = _capture_ollama_payload(analyzer)

        self.assertEqual(payload["options"]["seed"], 42)
        self.assertEqual(payload["options"]["temperature"], 0.1)

    def test_seed_is_configurable(self):
        analyzer = LLMSecurityAnalyzer(
            model_name="qwen2.5-coder:3b", backend="ollama", llm_seed=7
        )
        self.assertEqual(_capture_ollama_payload(analyzer)["options"]["seed"], 7)


class TestSeedCliAndSummary(unittest.TestCase):
    def test_cli_defaults_to_42_and_accepts_an_override(self):
        # source_dir is a required positional argument of this CLI.
        self.assertEqual(parse_args(["some/dir"]).llm_seed, 42)
        self.assertEqual(parse_args(["some/dir", "--llm-seed", "1234"]).llm_seed, 1234)

    def test_benchmark_cli_exposes_the_same_flag(self):
        args = ev.parse_args([])
        self.assertEqual(args.llm_seed, 42)
        self.assertEqual(ev.parse_args(["--llm-seed", "1234"]).llm_seed, 1234)

    def test_benchmark_summary_records_the_seed(self):
        summary_path = (
            REPO_ROOT / "models" / "audit" / "audit-results" / "test_run" / "summary.json"
        )
        args = ev.parse_args(
            ["--llm-seed", "1234", "--results-dir", str(summary_path.parent)]
        )
        self.assertEqual(args.llm_seed, 1234)
        self.assertIn("llm_seed", ev.run_metadata(args))

    def test_benchmark_passes_the_seed_into_the_analyzer(self):
        """A seed that is parsed but never reaches the analyzer pins nothing."""
        captured = {}

        class StubAnalyzer:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        with patch.object(ev, "LLMSecurityAnalyzer", StubAnalyzer):
            ev.build_analyzer("qwen2.5-coder:3b", "ollama", 1234)
        self.assertEqual(captured.get("llm_seed"), 1234)


if __name__ == "__main__":
    unittest.main()
