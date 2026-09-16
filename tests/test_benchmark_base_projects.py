"""
Tests for Audit-100 v2 Benchmark industrial base projects.
Verifies structure, syntax compilation, data assets, lifecycle hooks, and zero security findings.
"""

import os
import re
import json
import py_compile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BASE_PROJECTS_DIR = REPO_ROOT / "models" / "audit" / "benchmarks" / "base-projects"

# 13 production static security rules (mirrored from internal/codeaudit/rules.go)
PRODUCTION_STATIC_RULES = [
    {
        "id": "NET_001",
        "patterns": [
            r"requests\.(get|post|put|delete|patch|head)\s*\(",
            r"urllib\.request\.(urlopen|urlretrieve)",
            r"http\.client\.HTTPS?Connection",
            r"httpx\.(get|post|put|delete)\s*\(",
            r"aiohttp\.ClientSession",
            r"httplib2\.Http",
        ],
    },
    {
        "id": "NET_002",
        "patterns": [
            r"socket\.socket\s*\(",
            r"socket\.create_connection",
            r"\.connect\s*\(\s*[\('\"]",
            r"\.sendall?\s*\(",
        ],
    },
    {
        "id": "CMD_001",
        "patterns": [
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"os\.exec[a-z]*\s*\(",
            r"commands\.getoutput",
            r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
            r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*\[\s*['\"](?:bash|sh|zsh|fish|echo|curl|wget|rm|cmd\.exe|powershell|pwsh)['\"]",
            r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*['\"](?:bash|sh|zsh|fish|echo|curl|wget|rm|cmd\.exe|powershell|pwsh)['\"]",
            r"subprocess\.(run|call|Popen|check_output)",
        ],
    },
    {
        "id": "OBF_001",
        "patterns": [
            r"base64\.(b64decode|b64encode)\s*\(",
            r"pickle\.loads?\s*\(",
            r"marshal\.loads?\s*\(",
            r"zlib\.decompress\s*\(",
            r"codecs\.decode\s*\(",
            r"binascii\.(a2b|b2a)",
        ],
    },
    {
        "id": "DYN_001",
        "patterns": [
            r"(?:^|[^.\w])eval\s*\(",
            r"(?:^|[^.\w])exec\s*\(",
            r"compile\s*\(.*['\"]exec['\"]",
            r"__import__\s*\(",
            r"importlib\.import_module\s*\(",
        ],
    },
    {
        "id": "FIL_001",
        "patterns": [
            r"open\s*\(\s*['\"].*(?:\.ssh|\.env|password|credential|\.aws|\.kube|id_rsa|authorized_keys)",
            r"Path\s*\(\s*['\"].*(?:\.ssh|\.env|password|credential|\.aws|\.kube)[^)]*\)\.(?:read_text|read_bytes|open)\s*\(",
            r"Path\.home\(\)\.joinpath\([^)]*(?:\.ssh|\.env|password|credential|\.aws|\.kube|id_rsa|authorized_keys)[^)]*\)\.(?:read_text|read_bytes|open)\s*\(",
        ],
    },
    {
        "id": "ENV_001",
        "patterns": [
            r"os\.environ\s*[.\[]\s*['\"](?:[^'\"]*(?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key|password|passwd|pwd|cred|credential|auth|session|cookie|kube|aws|gcp|azure|github|gitlab)[^'\"]*)['\"]",
            r"os\.environ\.get\s*\(\s*['\"](?:[^'\"]*(?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key|password|passwd|pwd|cred|credential|auth|session|cookie|kube|aws|gcp|azure|github|gitlab)[^'\"]*)['\"]",
            r"os\.getenv\s*\(\s*['\"](?:[^'\"]*(?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key|password|passwd|pwd|cred|credential|auth|session|cookie|kube|aws|gcp|azure|github|gitlab)[^'\"]*)['\"]",
        ],
    },
    {
        "id": "PER_001",
        "patterns": [
            r"crontab|cron\.tab",
            r"\.bashrc|\.bash_profile|\.zshrc|\.profile",
            r"systemctl\s+(enable|start)",
            r"/etc/init\.d",
            r"/etc/systemd",
        ],
    },
    {
        "id": "EXF_001",
        "patterns": [
            r"base64.*request|request.*base64",
            r"json\.dumps.*post|post.*json\.dumps",
            r"encode.*send|send.*encode",
            r"upload.*file|file.*upload",
        ],
    },
    {
        "id": "EMB_001",
        "patterns": [
            r"torch\.save\s*\(\s*(?:raw_|train_|test_)?(?:data|dataset|images|samples|x_train|y_train)\b",
            r"np\.save\s*\(\s*['\"][^'\"]*['\"]\s*,\s*(?:raw_|train_|test_)?(?:data|dataset|images|samples|x_train|y_train)\b",
            r"np\.savez\s*\(\s*['\"][^'\"]*['\"]\s*,[^)]*(?:raw_|train_|test_)?(?:data|dataset|images|samples|x_train|y_train)\s*=",
            r"shutil\.copy\s*\([^)]*(?:data|dataset|train|test|image)\b",
            r"shutil\.copytree\s*\([^)]*(?:data|dataset|train|test|image)\b",
        ],
    },
    {
        "id": "EMB_002",
        "patterns": [
            r"shutil\.(copy|copytree|move)\s*\(.*output",
            r"shutil\.(copy|copytree|move)\s*\(.*export",
            r"shutil\.(copy|copytree|move)\s*\(.*result",
            r"os\.rename\s*\(.*data.*output",
            r"os\.rename\s*\(.*data.*result",
        ],
    },
    {
        "id": "EMB_003",
        "patterns": [
            r"print\s*\(\s*(?:raw_|train_|test_)?(?:data|dataset|images|samples|batch|x_train|y_train)\b",
            r"logging\.(?:info|debug|warning)\s*\(\s*(?:raw_|train_|test_)?(?:data|dataset|images|samples|batch|x_train|y_train)\b",
            r"sys\.stdout\.write\s*\(\s*(?:raw_|train_|test_)?(?:data|dataset|images|samples|batch|x_train|y_train)\b",
        ],
    },
    {
        "id": "EMB_004",
        "patterns": [
            r"(?:state_dict|weights|params).*(?:hidden|secret|payload|stego|embed|hide)(?:_?data)?",
            r"base64.*save|save.*base64",
            r"encode.*state_dict|state_dict.*encode",
            r"zlib.*save|save.*zlib",
            r"pickle\.dump\s*\(.*(data|dataset|images|samples)",
        ],
    },
]


def scan_file_for_rules(file_path: Path):
    """Scans a file against PRODUCTION_STATIC_RULES and returns findings."""
    findings = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    compiled = []
    for r in PRODUCTION_STATIC_RULES:
        for p in r["patterns"]:
            compiled.append((r["id"], re.compile(p)))

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for rule_id, regex in compiled:
            if regex.search(line):
                findings.append({
                    "file": str(file_path),
                    "line": i,
                    "rule_id": rule_id,
                    "snippet": stripped,
                })
    return findings


class TestBenchmarkBaseProjects(unittest.TestCase):
    EXPECTED_BASES = [
        "p1_xgboost_finance",
        "p2_retina_resnet",
        "p3_detection_industrial",
        "p4_bert_sentiment",
    ]

    def test_base_projects_exist_and_compile(self):
        """Verify all 4 base project directories and core files exist and compile cleanly."""
        self.assertTrue(BASE_PROJECTS_DIR.is_dir(), f"Base projects dir not found: {BASE_PROJECTS_DIR}")
        for base_name in self.EXPECTED_BASES:
            base_dir = BASE_PROJECTS_DIR / base_name
            self.assertTrue(base_dir.is_dir(), f"Base project directory missing: {base_dir}")
            for py_name in ["train.py", "dataset.py", "model.py"]:
                py_file = base_dir / py_name
                self.assertTrue(py_file.is_file(), f"Core file missing: {py_file}")
                # Must compile cleanly without syntax errors
                py_compile.compile(str(py_file), doraise=True)
            self.assertTrue((base_dir / "data").is_dir(), f"Data directory missing: {base_dir / 'data'}")

    def test_base_projects_data_assets(self):
        """Verify embedded micro-datasets are valid and complete."""
        # P1: creditcard_sample.csv
        p1_csv = BASE_PROJECTS_DIR / "p1_xgboost_finance" / "data" / "creditcard_sample.csv"
        self.assertTrue(p1_csv.is_file(), f"P1 creditcard_sample.csv missing: {p1_csv}")
        with open(p1_csv, "r", encoding="utf-8") as f:
            csv_lines = [line.strip() for line in f if line.strip()]
        header = csv_lines[0].split(",")
        self.assertIn("Time", header)
        self.assertIn("Amount", header)
        self.assertIn("Class", header)
        for i in range(1, 29):
            self.assertIn(f"V{i}", header)
        # 100 rows + 1 header = 101 lines
        self.assertGreaterEqual(len(csv_lines), 101, f"Expected at least 100 sample rows, got {len(csv_lines) - 1}")

        # P2: retina images
        p2_data = BASE_PROJECTS_DIR / "p2_retina_resnet" / "data"
        p2_pngs = list(p2_data.glob("*.png"))
        self.assertGreaterEqual(len(p2_pngs), 5, f"Expected at least 5 retina PNGs, found {len(p2_pngs)}")
        png_magic = b"\x89PNG\r\n\x1a\n"
        for png in p2_pngs:
            with open(png, "rb") as f:
                header_bytes = f.read(8)
            self.assertEqual(header_bytes, png_magic, f"{png.name} is not a valid PNG")

        # P3: industrial defect images + annotations.yaml
        p3_data = BASE_PROJECTS_DIR / "p3_detection_industrial" / "data"
        p3_pngs = list(p3_data.glob("*.png"))
        self.assertGreaterEqual(len(p3_pngs), 5, f"Expected at least 5 industrial PNGs, found {len(p3_pngs)}")
        for png in p3_pngs:
            with open(png, "rb") as f:
                header_bytes = f.read(8)
            self.assertEqual(header_bytes, png_magic, f"{png.name} is not a valid PNG")
        p3_ann = p3_data / "annotations.yaml"
        self.assertTrue(p3_ann.is_file(), f"P3 annotations.yaml missing: {p3_ann}")

        # P4: vocab.txt and reviews.jsonl
        p4_data = BASE_PROJECTS_DIR / "p4_bert_sentiment" / "data"
        p4_vocab = p4_data / "vocab.txt"
        self.assertTrue(p4_vocab.is_file(), f"P4 vocab.txt missing: {p4_vocab}")
        with open(p4_vocab, "r", encoding="utf-8") as f:
            vocab_tokens = [w.strip() for w in f if w.strip()]
        self.assertGreaterEqual(len(vocab_tokens), 50, f"Expected at least 50 vocab tokens, got {len(vocab_tokens)}")

        p4_reviews = p4_data / "reviews.jsonl"
        self.assertTrue(p4_reviews.is_file(), f"P4 reviews.jsonl missing: {p4_reviews}")
        with open(p4_reviews, "r", encoding="utf-8") as f:
            review_lines = [json.loads(line) for line in f if line.strip()]
        self.assertGreaterEqual(len(review_lines), 20, f"Expected at least 20 review samples, got {len(review_lines)}")
        for item in review_lines:
            self.assertIn("text", item)
            self.assertIn("label", item)

    def test_lifecycle_hook_present(self):
        """Verify each train.py includes the benchmark_variant.on_epoch_end lifecycle hook."""
        for base_name in self.EXPECTED_BASES:
            train_py = BASE_PROJECTS_DIR / base_name / "train.py"
            self.assertTrue(train_py.is_file(), f"Missing train.py in {base_name}")
            with open(train_py, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn(
                "benchmark_variant.on_epoch_end",
                content,
                f"Lifecycle hook missing in {train_py}",
            )

    def test_zero_security_findings(self):
        """Strict baseline sanitization gate: 0 findings against all static rules."""
        total_findings = []
        for base_name in self.EXPECTED_BASES:
            base_dir = BASE_PROJECTS_DIR / base_name
            if not base_dir.is_dir():
                continue
            for py_file in base_dir.rglob("*.py"):
                findings = scan_file_for_rules(py_file)
                total_findings.extend(findings)

        if total_findings:
            msg = f"Found {len(total_findings)} baseline security findings:\n"
            for f in total_findings:
                msg += f"  [{f['rule_id']}] {f['file']}:{f['line']} -> {f['snippet']}\n"
            self.assertEqual(len(total_findings), 0, msg)

        # Also verify with models/examples/code_security_analyzer.py StaticScanner
        analyzer_path = REPO_ROOT / "models" / "examples"
        import sys
        if str(analyzer_path) not in sys.path:
            sys.path.insert(0, str(analyzer_path))
        try:
            from code_security_analyzer import StaticScanner
            scanner = StaticScanner()
            analyzer_findings = []
            for base_name in self.EXPECTED_BASES:
                base_dir = BASE_PROJECTS_DIR / base_name
                for py_file in base_dir.rglob("*.py"):
                    af = scanner.scan_file(str(py_file))
                    if af:
                        analyzer_findings.extend(af)
            self.assertEqual(len(analyzer_findings), 0, f"StaticScanner found {len(analyzer_findings)} findings")
        except ImportError:
            pass

    def test_size_budget(self):
        """Verify each base project size is strictly under 1MB."""
        for base_name in self.EXPECTED_BASES:
            base_dir = BASE_PROJECTS_DIR / base_name
            self.assertTrue(base_dir.is_dir(), f"Directory missing: {base_dir}")
            total_size = sum(
                f.stat().st_size
                for f in base_dir.rglob("*")
                if f.is_file() and "output" not in f.parts and "__pycache__" not in f.parts
            )
            self.assertLess(
                total_size,
                1024 * 1024,
                f"{base_name} total size {total_size} bytes exceeds 1MB limit",
            )


if __name__ == "__main__":
    unittest.main()
