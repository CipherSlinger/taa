#!/usr/bin/env python3
import io
import json
import os
import ssl
import sys
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from list_models import (
    fetch_json,
    format_table,
    main,
    normalize_url,
    parse_claude_relay_response,
    parse_ollama_response,
    parse_openai_response,
    probe_models,
    resolve_config,
)


class TestNormalizeUrl(unittest.TestCase):
    def test_normalize_url_with_path(self):
        clean, root = normalize_url("https://cc.sususu.cf/api")
        self.assertEqual(clean, "https://cc.sususu.cf/api")
        self.assertEqual(root, "https://cc.sususu.cf")

    def test_normalize_url_with_trailing_slash(self):
        clean, root = normalize_url("http://127.0.0.1:11434/")
        self.assertEqual(clean, "http://127.0.0.1:11434")
        self.assertEqual(root, "http://127.0.0.1:11434")

    def test_normalize_url_without_scheme(self):
        clean, root = normalize_url("example.com/v1")
        self.assertEqual(clean, "http://example.com/v1")
        self.assertEqual(root, "http://example.com")

    def test_normalize_url_root_only(self):
        clean, root = normalize_url("https://api.openai.com")
        self.assertEqual(clean, "https://api.openai.com")
        self.assertEqual(root, "https://api.openai.com")

    def test_normalize_url_empty_or_whitespace(self):
        self.assertEqual(normalize_url(""), ("", ""))
        self.assertEqual(normalize_url(None), ("", ""))
        self.assertEqual(normalize_url("   "), ("", ""))


class TestParseClaudeRelayResponse(unittest.TestCase):
    def test_parse_grouped_claude_relay(self):
        sample = {
            "success": True,
            "data": {
                "claude": [{"value": "claude-opus-4-6", "label": "Claude Opus 4.6"}],
                "gemini": [{"value": "gemini-2.5-pro", "label": "Gemini 2.5 Pro"}],
                "openai": [{"value": "gpt-5", "label": "GPT-5"}],
                "other": [{"value": "qwen", "label": "Qwen"}],
            },
        }
        models = parse_claude_relay_response(sample)
        self.assertEqual(len(models), 4)
        self.assertEqual(models[0], {
            "id": "claude-opus-4-6",
            "label": "Claude Opus 4.6",
            "group": "claude",
        })
        self.assertEqual(models[1], {
            "id": "gemini-2.5-pro",
            "label": "Gemini 2.5 Pro",
            "group": "gemini",
        })
        self.assertEqual(models[2], {
            "id": "gpt-5",
            "label": "GPT-5",
            "group": "openai",
        })
        self.assertEqual(models[3], {
            "id": "qwen",
            "label": "Qwen",
            "group": "other",
        })

    def test_parse_claude_relay_fallback_to_all(self):
        sample = {
            "success": True,
            "data": {
                "all": [
                    {"value": "model-from-all-1", "label": "Model 1", "provider": "openai"},
                    {"value": "model-from-all-2", "label": "Model 2", "group": "anthropic"},
                ]
            },
        }
        models = parse_claude_relay_response(sample)
        self.assertEqual(len(models), 2)
        self.assertEqual(models[0]["id"], "model-from-all-1")
        self.assertEqual(models[0]["group"], "openai")
        self.assertEqual(models[1]["id"], "model-from-all-2")
        self.assertEqual(models[1]["group"], "anthropic")

    def test_parse_claude_relay_deduplication(self):
        sample = {
            "success": True,
            "data": {
                "claude": [
                    {"value": "claude-dup", "label": "Dup 1"},
                    {"value": "claude-dup", "label": "Dup 2"},
                ]
            },
        }
        models = parse_claude_relay_response(sample)
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["id"], "claude-dup")

    def test_parse_claude_relay_invalid_or_empty(self):
        self.assertEqual(parse_claude_relay_response(None), [])
        self.assertEqual(parse_claude_relay_response({}), [])
        self.assertEqual(parse_claude_relay_response({"success": False}), [])
        self.assertEqual(parse_claude_relay_response({"success": True, "data": {}}), [])


class TestParseOpenaiResponse(unittest.TestCase):
    def test_parse_standard_openai(self):
        sample = {
            "object": "list",
            "data": [
                {"id": "gpt-4o", "owned_by": "openai"},
                {"id": "deepseek-r1", "owned_by": "deepseek"},
            ],
        }
        models = parse_openai_response(sample)
        self.assertEqual(len(models), 2)
        self.assertEqual(models[0], {
            "id": "gpt-4o",
            "label": "gpt-4o",
            "group": "openai",
        })
        self.assertEqual(models[1], {
            "id": "deepseek-r1",
            "label": "deepseek-r1",
            "group": "deepseek",
        })

    def test_parse_openai_missing_owned_by(self):
        sample = {
            "data": [
                {"id": "custom-model"}
            ]
        }
        models = parse_openai_response(sample)
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0], {
            "id": "custom-model",
            "label": "custom-model",
            "group": "openai",
        })

    def test_parse_openai_deduplication(self):
        sample = {
            "data": [
                {"id": "gpt-4o", "owned_by": "openai"},
                {"id": "gpt-4o", "owned_by": "openai"},
            ]
        }
        models = parse_openai_response(sample)
        self.assertEqual(len(models), 1)

    def test_parse_openai_invalid(self):
        self.assertEqual(parse_openai_response(None), [])
        self.assertEqual(parse_openai_response({}), [])
        self.assertEqual(parse_openai_response({"data": "not a list"}), [])


class TestParseOllamaResponse(unittest.TestCase):
    def test_parse_standard_ollama(self):
        sample = {
            "models": [
                {"name": "qwen2.5-coder:3b", "details": {"parameter_size": "3B"}},
                {"name": "llama3.2:latest", "details": {"parameter_size": "3B"}},
            ]
        }
        models = parse_ollama_response(sample)
        self.assertEqual(len(models), 2)
        self.assertEqual(models[0], {
            "id": "qwen2.5-coder:3b",
            "label": "qwen2.5-coder:3b (3B)",
            "group": "ollama",
        })
        self.assertEqual(models[1], {
            "id": "llama3.2:latest",
            "label": "llama3.2:latest (3B)",
            "group": "ollama",
        })

    def test_parse_ollama_without_details(self):
        sample = {
            "models": [
                {"name": "mistral:7b"}
            ]
        }
        models = parse_ollama_response(sample)
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0], {
            "id": "mistral:7b",
            "label": "mistral:7b",
            "group": "ollama",
        })

    def test_parse_ollama_deduplication(self):
        sample = {
            "models": [
                {"name": "llama3.2:latest"},
                {"name": "llama3.2:latest"},
            ]
        }
        models = parse_ollama_response(sample)
        self.assertEqual(len(models), 1)

    def test_parse_ollama_invalid(self):
        self.assertEqual(parse_ollama_response(None), [])
        self.assertEqual(parse_ollama_response({}), [])
        self.assertEqual(parse_ollama_response({"models": "invalid"}), [])


class DummyArgs:
    def __init__(self, url=None, key=None):
        self.url = url
        self.key = key


class TestResolveConfig(unittest.TestCase):
    def test_cli_args_precedence(self):
        args = DummyArgs(url="http://custom.com", key="custom-key")
        env = {
            "BASE_URL": "http://base.com",
            "ANTHROPIC_BASE_URL": "http://anthropic.com",
            "OPENAI_BASE_URL": "http://openai.com",
            "API_KEY": "base-key",
            "ANTHROPIC_AUTH_TOKEN": "anthropic-key",
            "OPENAI_API_KEY": "openai-key",
        }
        url, key = resolve_config(args, env)
        self.assertEqual(url, "http://custom.com")
        self.assertEqual(key, "custom-key")

    def test_url_fallback_chain(self):
        args = DummyArgs(url=None, key=None)

        # 1. BASE_URL
        env1 = {"BASE_URL": "http://base.com"}
        url1, _ = resolve_config(args, env1)
        self.assertEqual(url1, "http://base.com")

        # 2. ANTHROPIC_BASE_URL
        env2 = {"ANTHROPIC_BASE_URL": "http://anthropic.com"}
        url2, _ = resolve_config(args, env2)
        self.assertEqual(url2, "http://anthropic.com")

        # 3. OPENAI_BASE_URL
        env3 = {"OPENAI_BASE_URL": "http://openai.com"}
        url3, _ = resolve_config(args, env3)
        self.assertEqual(url3, "http://openai.com")

        # 4. None
        url4, _ = resolve_config(args, {})
        self.assertIsNone(url4)

    def test_key_fallback_chain(self):
        args = DummyArgs(url="http://test.com", key=None)

        # 1. API_KEY
        env1 = {"API_KEY": "key1"}
        _, key1 = resolve_config(args, env1)
        self.assertEqual(key1, "key1")

        # 2. ANTHROPIC_AUTH_TOKEN
        env2 = {"ANTHROPIC_AUTH_TOKEN": "key2"}
        _, key2 = resolve_config(args, env2)
        self.assertEqual(key2, "key2")

        # 3. OPENAI_API_KEY
        env3 = {"OPENAI_API_KEY": "key3"}
        _, key3 = resolve_config(args, env3)
        self.assertEqual(key3, "key3")

        # 4. None
        _, key4 = resolve_config(args, {})
        self.assertIsNone(key4)

    def test_key_sanitization(self):
        args = DummyArgs(url="http://test.com", key="  secret-key  ")
        _, key = resolve_config(args, {})
        self.assertEqual(key, "secret-key")

        args_empty = DummyArgs(url="http://test.com", key="   ")
        _, key_empty = resolve_config(args_empty, {})
        self.assertIsNone(key_empty)


class TestFetchJson(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_fetch_json_200_ok(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"status": "ok", "count": 42}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        status, data, err = fetch_json("http://example.com/api")
        self.assertEqual(status, 200)
        self.assertEqual(data, {"status": "ok", "count": 42})
        self.assertIsNone(err)

    @patch("urllib.request.urlopen")
    def test_fetch_json_http_error_401(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://example.com/api", 401, "Unauthorized", {}, None
        )
        status, data, err = fetch_json("http://example.com/api")
        self.assertEqual(status, 401)
        self.assertIsNone(data)
        self.assertIn("HTTP Error 401", err)
        self.assertIn("Unauthorized", err)

    @patch("urllib.request.urlopen")
    def test_fetch_json_http_error_404(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://example.com/api", 404, "Not Found", {}, None
        )
        status, data, err = fetch_json("http://example.com/api")
        self.assertEqual(status, 404)
        self.assertIsNone(data)
        self.assertIn("HTTP Error 404", err)
        self.assertIn("Not Found", err)

    @patch("urllib.request.urlopen")
    def test_fetch_json_url_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        status, data, err = fetch_json("http://example.com/api")
        self.assertEqual(status, 0)
        self.assertIsNone(data)
        self.assertIn("URL Error", err)
        self.assertIn("Connection refused", err)

    @patch("urllib.request.urlopen")
    def test_fetch_json_decode_error(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"Not JSON content <html />"
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        status, data, err = fetch_json("http://example.com/api")
        self.assertEqual(status, 200)
        self.assertIsNone(data)
        self.assertIn("JSON Decode Error", err)

    @patch("urllib.request.urlopen")
    def test_fetch_json_headers_propagation(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"{}"
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        status, data, err = fetch_json("http://example.com/api", token="  test-secret-token  ")
        self.assertEqual(status, 200)

        self.assertTrue(mock_urlopen.called)
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_header("Authorization"), "Bearer test-secret-token")
        self.assertEqual(req.get_header("X-api-key"), "test-secret-token")

    @patch("urllib.request.urlopen")
    @patch("ssl._create_unverified_context")
    @patch("ssl.create_default_context")
    def test_fetch_json_ssl_context_configuration(
        self, mock_default_ctx, mock_unverified_ctx, mock_urlopen
    ):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"{}"
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        # Case insecure=False
        fetch_json("https://example.com", insecure=False)
        self.assertTrue(mock_default_ctx.called)
        self.assertFalse(mock_unverified_ctx.called)

        mock_default_ctx.reset_mock()
        mock_unverified_ctx.reset_mock()

        # Case insecure=True
        fetch_json("https://example.com", insecure=True)
        self.assertFalse(mock_default_ctx.called)
        self.assertTrue(mock_unverified_ctx.called)


class TestFormatTable(unittest.TestCase):
    def test_format_table_output(self):
        models = [
            {"id": "claude-3-5-sonnet", "label": "Claude 3.5 Sonnet", "group": "claude"},
            {"id": "gpt-4o", "label": "gpt-4o", "group": "openai"},
        ]
        table = format_table(models, base_url="https://cc.sususu.cf/api", protocol="claude-relay")
        self.assertIn("claude-3-5-sonnet", table)
        self.assertIn("gpt-4o", table)
        self.assertIn("Total: 2 models found", table)
        self.assertIn("claude-relay", table)


class TestProbeModels(unittest.TestCase):
    @patch("list_models.fetch_json")
    def test_probe_claude_relay_success(self, mock_fetch):
        mock_fetch.return_value = (
            200,
            {
                "success": True,
                "data": {
                    "claude": [{"value": "claude-3-haiku", "label": "Claude 3 Haiku"}],
                },
            },
            None,
        )
        models, protocol, endpoint, history = probe_models("https://example.com/api")
        self.assertEqual(protocol, "claude-relay")
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["id"], "claude-3-haiku")
        self.assertEqual(endpoint, "https://example.com/apiStats/models")
        self.assertEqual(len(history), 0)

    @patch("list_models.fetch_json")
    def test_probe_openai_fallback_success(self, mock_fetch):
        def side_effect(url, **kwargs):
            if "/apiStats/models" in url:
                return (404, None, "Not Found")
            if "/v1/models" in url:
                return (
                    200,
                    {
                        "data": [{"id": "gpt-4o-mini", "owned_by": "openai"}],
                    },
                    None,
                )
            return (404, None, "Not Found")

        mock_fetch.side_effect = side_effect
        models, protocol, endpoint, history = probe_models("https://api.openai.com")
        self.assertEqual(protocol, "openai")
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["id"], "gpt-4o-mini")
        self.assertTrue(len(history) >= 1)

    @patch("list_models.fetch_json")
    def test_probe_ollama_fallback_success(self, mock_fetch):
        def side_effect(url, **kwargs):
            if "/tags" in url:
                return (
                    200,
                    {
                        "models": [{"name": "qwen2.5:7b"}],
                    },
                    None,
                )
            return (404, None, "Not Found")

        mock_fetch.side_effect = side_effect
        models, protocol, endpoint, history = probe_models("http://127.0.0.1:11434")
        self.assertEqual(protocol, "ollama")
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["id"], "qwen2.5:7b")

    @patch("list_models.fetch_json")
    def test_probe_all_failed(self, mock_fetch):
        mock_fetch.return_value = (404, None, "Not Found")
        models, protocol, endpoint, history = probe_models("http://invalid.host")
        self.assertEqual(models, [])
        self.assertEqual(protocol, "")
        self.assertEqual(endpoint, "")
        self.assertTrue(len(history) > 0)

    @patch("list_models.fetch_json")
    def test_probe_models_no_duplicate_v1_path(self, mock_fetch):
        attempted_urls = []

        def side_effect(url, **kwargs):
            attempted_urls.append(url)
            return (404, None, "Not Found")

        mock_fetch.side_effect = side_effect
        probe_models("https://api.openai.com/v1")
        for u in attempted_urls:
            self.assertNotIn("/v1/v1", u)

    @patch("list_models.fetch_json")
    def test_probe_models_no_duplicate_api_path(self, mock_fetch):
        attempted_urls = []

        def side_effect(url, **kwargs):
            attempted_urls.append(url)
            return (404, None, "Not Found")

        mock_fetch.side_effect = side_effect
        probe_models("http://127.0.0.1:11434/api")
        for u in attempted_urls:
            self.assertNotIn("/api/api", u)

    def test_probe_models_empty_url(self):
        models, protocol, endpoint, history = probe_models("")
        self.assertEqual(models, [])
        self.assertEqual(protocol, "")
        self.assertEqual(endpoint, "")
        self.assertEqual(history, [])


class TestCliModesAndHandling(unittest.TestCase):
    @patch("list_models.probe_models")
    def test_cli_raw_mode(self, mock_probe):
        mock_probe.return_value = (
            [
                {"id": "model-alpha", "label": "Model Alpha", "group": "openai"},
                {"id": "model-beta", "label": "Model Beta", "group": "openai"},
            ],
            "openai",
            "https://api.openai.com/v1/models",
            [],
        )
        with patch("sys.argv", ["list_models.py", "-u", "https://api.openai.com", "--raw"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as cm:
                    main()
                self.assertEqual(cm.exception.code, 0)
                output = mock_out.getvalue().strip().splitlines()
                self.assertEqual(output, ["model-alpha", "model-beta"])

    @patch("list_models.probe_models")
    def test_cli_json_mode(self, mock_probe):
        mock_probe.return_value = (
            [{"id": "model-alpha", "label": "Model Alpha", "group": "openai"}],
            "openai",
            "https://api.openai.com/v1/models",
            [],
        )
        with patch("sys.argv", ["list_models.py", "-u", "https://api.openai.com", "--json"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as cm:
                    main()
                self.assertEqual(cm.exception.code, 0)
                parsed = json.loads(mock_out.getvalue())
                self.assertEqual(len(parsed), 1)
                self.assertEqual(parsed[0]["id"], "model-alpha")

    @patch("list_models.probe_models")
    def test_cli_broken_pipe_handling(self, mock_probe):
        mock_probe.return_value = (
            [{"id": "model-alpha", "label": "Model Alpha", "group": "openai"}],
            "openai",
            "https://api.openai.com/v1/models",
            [],
        )
        with patch("sys.argv", ["list_models.py", "-u", "https://api.openai.com", "--raw"]):
            with patch("sys.stdout", new_callable=io.StringIO):
                with patch("sys.stderr"):
                    with patch("sys.stdout.flush", side_effect=BrokenPipeError):
                        with self.assertRaises(SystemExit) as cm:
                            main()
                        self.assertEqual(cm.exception.code, 0)

    @patch("list_models.probe_models")
    def test_cli_diagnostics_auth_error(self, mock_probe):
        mock_probe.return_value = (
            [],
            "",
            "",
            [("https://api.openai.com/v1/models", 401, "HTTP Error 401: Unauthorized")],
        )
        with patch("sys.argv", ["list_models.py", "-u", "https://api.openai.com"]):
            with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                with self.assertRaises(SystemExit) as cm:
                    main()
                self.assertEqual(cm.exception.code, 2)
                err_text = mock_err.getvalue()
                self.assertIn("Probe Diagnostics:", err_text)
                self.assertIn("401", err_text)
                self.assertIn("Authentication failed", err_text)

    @patch("list_models.probe_models")
    def test_cli_diagnostics_ssl_error(self, mock_probe):
        mock_probe.return_value = (
            [],
            "",
            "",
            [("https://internal.gw/v1/models", 0, "URL Error: [SSL: CERTIFICATE_VERIFY_FAILED]")],
        )
        with patch("sys.argv", ["list_models.py", "-u", "https://internal.gw"]):
            with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                with self.assertRaises(SystemExit) as cm:
                    main()
                self.assertEqual(cm.exception.code, 2)
                err_text = mock_err.getvalue()
                self.assertIn("Probe Diagnostics:", err_text)
                self.assertIn("SSL certificate verification failed", err_text)
                self.assertIn("--insecure", err_text)


class TestCliExecution(unittest.TestCase):
    def test_cli_missing_url_fails(self):
        import subprocess
        res = subprocess.run(
            [sys.executable, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "list_models.py"))],
            env={},
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("BASE_URL is required", res.stderr)

    def test_cli_unreachable_fails(self):
        import subprocess
        res = subprocess.run(
            [
                sys.executable,
                os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "list_models.py")),
                "-u",
                "http://127.0.0.1:59998",
                "-t",
                "0.2",
            ],
            env={},
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn("Failed to probe models", res.stderr)


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()
