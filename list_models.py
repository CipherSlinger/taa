#!/usr/bin/env python3
"""
list_models.py - Universal and adaptive LLM models listing CLI.

Queries and lists available models from various LLM endpoints
(Claude Relay Service, OpenAI-compatible APIs, Ollama, etc.)
using Python 3 standard library only.
"""

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


def normalize_url(raw_url):
    """
    Normalize the input URL:
    - Add http:// prefix if scheme is missing.
    - Strip trailing slashes to get clean_url.
    - Extract scheme://netloc as root_url.
    Returns: (clean_url, root_url)
    """
    if not raw_url or not raw_url.strip():
        return "", ""
    url = raw_url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.rstrip("/")
    clean_url = f"{parsed.scheme}://{parsed.netloc}{path}"
    root_url = f"{parsed.scheme}://{parsed.netloc}"
    return clean_url, root_url


def resolve_config(args, env=None):
    """
    Resolve target URL and API Key with fallback priority:
    URL: args.url -> env["BASE_URL"] -> env["ANTHROPIC_BASE_URL"] -> env["OPENAI_BASE_URL"]
    Key: args.key -> env["API_KEY"] -> env["ANTHROPIC_AUTH_TOKEN"] -> env["OPENAI_API_KEY"]
    Returns: (url, key)
    """
    if env is None:
        env = os.environ

    url = getattr(args, "url", None)
    if not url:
        url = (
            env.get("BASE_URL")
            or env.get("ANTHROPIC_BASE_URL")
            or env.get("OPENAI_BASE_URL")
        )

    key = getattr(args, "key", None)
    if not key:
        key = (
            env.get("API_KEY")
            or env.get("ANTHROPIC_AUTH_TOKEN")
            or env.get("OPENAI_API_KEY")
        )

    if key:
        key = key.strip() if key.strip() else None

    return url, key


def parse_claude_relay_response(data):
    """
    Parse response from Claude Relay Service (/apiStats/models).
    Expected structure:
    {"success": True, "data": {"claude": [{"value": "...", "label": "..."}], ...}}
    """
    if not isinstance(data, dict):
        return []
    if data.get("success") is not True and "data" not in data:
        return []

    data_payload = data.get("data")
    if not isinstance(data_payload, dict):
        return []

    models = []
    seen_ids = set()

    # Prioritize well-known groups
    primary_groups = ["claude", "gemini", "openai", "other"]
    other_groups = [
        k for k in data_payload.keys()
        if k not in primary_groups and k not in ("all", "platforms")
    ]

    for group in primary_groups + other_groups:
        items = data_payload.get(group)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    model_id = item.get("value") or item.get("id") or item.get("name")
                    label = item.get("label") or model_id
                    if model_id and model_id not in seen_ids:
                        seen_ids.add(model_id)
                        models.append({
                            "id": model_id,
                            "label": label,
                            "group": group,
                        })

    # Fallback to "all" list if nothing extracted
    if not models and isinstance(data_payload.get("all"), list):
        for item in data_payload["all"]:
            if isinstance(item, dict):
                model_id = item.get("value") or item.get("id") or item.get("name")
                label = item.get("label") or model_id
                group = item.get("group") or item.get("provider") or "other"
                if model_id and model_id not in seen_ids:
                    seen_ids.add(model_id)
                    models.append({
                        "id": model_id,
                        "label": label,
                        "group": group,
                    })

    return models


def parse_openai_response(data):
    """
    Parse standard OpenAI response (/v1/models).
    Expected structure:
    {"object": "list", "data": [{"id": "gpt-4o", "owned_by": "openai"}, ...]}
    """
    if not isinstance(data, dict):
        return []
    items = data.get("data")
    if not isinstance(items, list):
        return []

    models = []
    seen_ids = set()
    for item in items:
        if isinstance(item, dict):
            model_id = item.get("id")
            if model_id and model_id not in seen_ids:
                seen_ids.add(model_id)
                group = item.get("owned_by") or "openai"
                models.append({
                    "id": model_id,
                    "label": model_id,
                    "group": group,
                })
    return models


def parse_ollama_response(data):
    """
    Parse Ollama response (/api/tags).
    Expected structure:
    {"models": [{"name": "qwen2.5-coder:3b", "details": {"parameter_size": "3B"}}]}
    """
    if not isinstance(data, dict):
        return []
    items = data.get("models")
    if not isinstance(items, list):
        return []

    models = []
    seen_ids = set()
    for item in items:
        if isinstance(item, dict):
            name = item.get("name") or item.get("model")
            if name and name not in seen_ids:
                seen_ids.add(name)
                details = item.get("details")
                param_size = None
                if isinstance(details, dict):
                    param_size = details.get("parameter_size")
                label = f"{name} ({param_size})" if param_size else name
                models.append({
                    "id": name,
                    "label": label,
                    "group": "ollama",
                })
    return models


def fetch_json(url, token=None, timeout=10, insecure=False):
    """
    Perform HTTP GET request and parse JSON response.
    Returns: (status_code, data_dict_or_None, error_message_or_None)
    """
    headers = {
        "User-Agent": "ModelLister/1.0",
        "Accept": "application/json",
    }
    if token:
        token = token.strip() if token.strip() else None
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["x-api-key"] = token

    ctx = None
    if insecure:
        ctx = ssl._create_unverified_context()
    else:
        ctx = ssl.create_default_context()

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status if hasattr(resp, "status") else resp.getcode()
            body = resp.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
                return status, data, None
            except json.JSONDecodeError as err:
                return status, None, f"JSON Decode Error: {err}"
    except urllib.error.HTTPError as err:
        return err.code, None, f"HTTP Error {err.code}: {err.reason}"
    except urllib.error.URLError as err:
        return 0, None, f"URL Error: {err.reason}"
    except Exception as err:
        return 0, None, f"Request Error: {err}"


def probe_models(base_url, token=None, timeout=10, insecure=False):
    """
    Probe the base_url with supported protocols in sequence:
    1. Claude Relay: {root_url}/apiStats/models
    2. OpenAI: {clean_url}/models, {clean_url}/v1/models, {root_url}/v1/models
    3. Ollama: {clean_url}/api/tags, {root_url}/api/tags
    Returns: (models, detected_protocol, final_url, probe_history)
    """
    if token:
        token = token.strip() if token.strip() else None
    clean_url, root_url = normalize_url(base_url)
    if not clean_url:
        return [], "", "", []

    probe_history = []

    # 1. Claude Relay probing
    relay_url = f"{root_url}/apiStats/models"
    status, data, err = fetch_json(relay_url, token=token, timeout=timeout, insecure=insecure)
    if status == 200 and data:
        models = parse_claude_relay_response(data)
        if models:
            return models, "claude-relay", relay_url, probe_history
        probe_history.append((relay_url, status, "Response did not contain valid models"))
    else:
        probe_history.append((relay_url, status, err or f"HTTP status {status}"))

    # 2. OpenAI probing
    # If clean_url ends with /v1, clean_url/models already gives .../v1/models.
    # Avoid generating .../v1/v1/models.
    openai_candidates = []
    openai_raw = [f"{clean_url}/models"]
    if not clean_url.endswith("/v1"):
        openai_raw.append(f"{clean_url}/v1/models")
    openai_raw.append(f"{root_url}/v1/models")
    for candidate in openai_raw:
        if candidate not in openai_candidates:
            openai_candidates.append(candidate)

    for url in openai_candidates:
        status, data, err = fetch_json(url, token=token, timeout=timeout, insecure=insecure)
        if status == 200 and data:
            models = parse_openai_response(data)
            if models:
                return models, "openai", url, probe_history
            probe_history.append((url, status, "Response did not contain valid models"))
        else:
            probe_history.append((url, status, err or f"HTTP status {status}"))

    # 3. Ollama probing
    # If clean_url ends with /api, use clean_url/tags to avoid /api/api/tags.
    ollama_candidates = []
    ollama_raw = [
        f"{clean_url}/tags" if clean_url.endswith("/api") else f"{clean_url}/api/tags",
        f"{root_url}/api/tags",
    ]
    for candidate in ollama_raw:
        if candidate not in ollama_candidates:
            ollama_candidates.append(candidate)

    for url in ollama_candidates:
        status, data, err = fetch_json(url, token=token, timeout=timeout, insecure=insecure)
        if status == 200 and data:
            models = parse_ollama_response(data)
            if models:
                return models, "ollama", url, probe_history
            probe_history.append((url, status, "Response did not contain valid models"))
        else:
            probe_history.append((url, status, err or f"HTTP status {status}"))

    return [], "", "", probe_history


def format_table(models, base_url, protocol):
    """
    Format models into a clean aligned terminal table.
    """
    lines = []
    lines.append(f"BASE_URL: {base_url}")
    lines.append(f"Detected Protocol: {protocol}")
    lines.append("")

    headers = ["#", "Group/Provider", "Model ID", "Label/Details"]

    # Calculate column widths
    w_idx = max(len(headers[0]), len(str(len(models))))
    w_grp = len(headers[1])
    w_id = len(headers[2])
    w_lbl = len(headers[3])

    for idx, m in enumerate(models, 1):
        w_grp = max(w_grp, len(str(m.get("group", ""))))
        w_id = max(w_id, len(str(m.get("id", ""))))
        w_lbl = max(w_lbl, len(str(m.get("label", ""))))

    sep_border = f"+-{'-' * w_idx}-+-{'-' * w_grp}-+-{'-' * w_id}-+-{'-' * w_lbl}-+"
    header_line = (
        f"| {headers[0].ljust(w_idx)} | {headers[1].ljust(w_grp)} | "
        f"{headers[2].ljust(w_id)} | {headers[3].ljust(w_lbl)} |"
    )

    lines.append(sep_border)
    lines.append(header_line)
    lines.append(sep_border)

    for idx, m in enumerate(models, 1):
        row = (
            f"| {str(idx).rjust(w_idx)} | {str(m.get('group', '')).ljust(w_grp)} | "
            f"{str(m.get('id', '')).ljust(w_id)} | {str(m.get('label', '')).ljust(w_lbl)} |"
        )
        lines.append(row)

    lines.append(sep_border)
    lines.append(f"Total: {len(models)} models found")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Query and list available LLM models from a given BASE_URL.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Fallback rules:
  --url falls back to: BASE_URL -> ANTHROPIC_BASE_URL -> OPENAI_BASE_URL
  --key falls back to: API_KEY -> ANTHROPIC_AUTH_TOKEN -> OPENAI_API_KEY
""",
    )
    parser.add_argument(
        "-u", "--url",
        dest="url",
        help="Target base URL (e.g. https://api.openai.com or http://127.0.0.1:11434)",
    )
    parser.add_argument(
        "-k", "--key",
        dest="key",
        help="API Key or Bearer Token for authentication",
    )
    parser.add_argument(
        "-r", "--raw",
        action="store_true",
        help="Output raw model IDs only (one per line)",
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output models list as formatted JSON",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip SSL certificate verification",
    )

    args = parser.parse_args()

    url, key = resolve_config(args)
    if not url:
        sys.stderr.write(
            "Error: BASE_URL is required. Provide -u/--url or set BASE_URL / "
            "ANTHROPIC_BASE_URL / OPENAI_BASE_URL in environment.\n"
        )
        sys.exit(1)

    models, protocol, endpoint, probe_history = probe_models(
        base_url=url,
        token=key,
        timeout=args.timeout,
        insecure=args.insecure,
    )

    if not models:
        sys.stderr.write(
            f"Error: Failed to probe models from '{url}'. "
            "All candidate endpoints failed or returned no models.\n"
        )
        if probe_history:
            sys.stderr.write("\nProbe Diagnostics:\n")
            has_auth_error = False
            has_ssl_error = False
            for attempted_url, status, error_msg in probe_history:
                status_str = str(status) if status else "N/A"
                sys.stderr.write(f"  - [{status_str}] {attempted_url}: {error_msg}\n")
                if status in (401, 403):
                    has_auth_error = True
                if error_msg and ("SSL" in error_msg or "certificate" in error_msg.lower()):
                    has_ssl_error = True

            sys.stderr.write("\nSuggestions:\n")
            if has_auth_error:
                sys.stderr.write(
                    "  * Authentication failed (HTTP 401/403). Please verify your API key or token via -k/--key.\n"
                )
            if has_ssl_error:
                sys.stderr.write(
                    "  * SSL certificate verification failed. If using an internal or self-signed endpoint, try --insecure.\n"
                )
            if not has_auth_error and not has_ssl_error:
                sys.stderr.write(
                    "  * Check if the host/port is correct and the service is running.\n"
                    "  * If the service requires authentication, provide an API key via -k/--key.\n"
                )
        sys.exit(2)

    try:
        if args.raw:
            for m in models:
                print(m["id"])
        elif args.json:
            print(json.dumps(models, indent=2, ensure_ascii=False))
        else:
            print(format_table(models, url, protocol))
        sys.stdout.flush()
    except BrokenPipeError:
        try:
            sys.stderr.close()
        except Exception:
            pass
        sys.exit(0)

    sys.exit(0)


if __name__ == "__main__":
    main()
