#!/usr/bin/env python3
"""Local preview and ShowDoc sync helper for docs/api-design.html.

A browser cannot fetch a local markdown file over file://, so the viewer page is
served from this tiny stdlib-only HTTP server. The same server exposes the
"sync to ShowDoc" action the page's button calls:

    GET  /                 the viewer page (docs/api-design.html)
    GET  /api-design.md    the document being previewed
    GET  /api/status       compare the local file with the online page
    POST /api/sync         publish the local file to the ShowDoc page

Configuration, first match wins:
    --config PATH, $SHOWDOC_CONFIG, ~/.config/taa-showdoc.json

Required keys: base (the ShowDoc index.php URL), user, pass.
Optional keys: page_id, item_id, cat_id, title, backup_dir.

Usage:
    python3 tools/showdoc-sync/serve.py [--port 8770] [--no-browser]

The server binds to 127.0.0.1 only and rejects cross-origin writes, since it
holds a ShowDoc session and can publish to the site.
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs"
PAGE_FILE = DOCS / "api-design.md"
VIEW_FILE = DOCS / "api-design.html"
DEFAULT_CONFIG = Path.home() / ".config" / "taa-showdoc.json"

# The save endpoint expects the body the SPA sends: page_content is already
# percent-encoded and is_urlencode=1 tells the server to decode it once more.
SAVE_URLENCODED = "1"


class SyncError(Exception):
    pass


def sha1(text):
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def load_config(path_arg):
    path = Path(path_arg or os.environ.get("SHOWDOC_CONFIG") or DEFAULT_CONFIG).expanduser()
    if not path.exists():
        raise SystemExit(
            "config not found: %s\n"
            "create it with: {\"base\": \"http://<host>/showdoc/server/index.php\","
            " \"user\": \"...\", \"pass\": \"...\", \"page_id\": \"...\","
            " \"item_id\": \"...\", \"cat_id\": \"...\", \"title\": \"...\"}" % path
        )
    cfg = json.loads(path.read_text(encoding="utf-8"))
    for key in ("base", "user", "pass", "page_id"):
        if not str(cfg.get(key, "")).strip():
            raise SystemExit("config %s: missing required key %r" % (path, key))
    cfg.setdefault("backup_dir", str(REPO / ".claude" / "backup"))
    cfg.setdefault("title", "")
    cfg["_path"] = str(path)
    return cfg


def api_url(cfg, api):
    return "%s?s=%s" % (cfg["base"].rstrip("/"), api)


def new_session():
    jar = urllib.request.HTTPCookieProcessor()
    return urllib.request.build_opener(jar)


def call(opener, cfg, api, fields=None, timeout=30):
    """Call a ShowDoc JSON API and return its data, raising on error_code != 0."""
    if fields is None:
        req = urllib.request.Request(api_url(cfg, api))
    else:
        body = urllib.parse.urlencode(fields).encode("utf-8")
        req = urllib.request.Request(
            api_url(cfg, api),
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        raise SyncError("%s 请求失败: %s" % (api, exc))
    try:
        payload = json.loads(raw)
    except ValueError:
        raise SyncError("%s 返回的不是 JSON: %s" % (api, raw[:200]))
    if payload.get("error_code") != 0:
        raise SyncError("%s 返回 error_code=%s: %s" % (api, payload.get("error_code"), payload.get("error_message")))
    return payload.get("data")


def login(cfg, opener):
    call(opener, cfg, "/api/user/login", {"username": cfg["user"], "password": cfg["pass"]})
    return opener


def fetch_online(cfg):
    opener = login(cfg, new_session())
    return call(opener, cfg, "/api/page/info&page_id=%s" % cfg["page_id"])


def local_text():
    return PAGE_FILE.read_text(encoding="utf-8")


def backup(cfg, content):
    out = Path(cfg["backup_dir"]).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    path = out / ("showdoc-%s-%s.md" % (cfg["page_id"], time.strftime("%Y%m%d-%H%M%S")))
    path.write_text(content, encoding="utf-8")
    return str(path)


def do_sync(force=False):
    cfg = CONFIG
    local = local_text()
    online_info = fetch_online(cfg)
    online = online_info.get("page_content", "")
    result = {
        "ok": True,
        "page_id": cfg["page_id"],
        "title": cfg["title"] or online_info.get("page_title", ""),
        "local_chars": len(local),
        "local_sha1": sha1(local),
        "online_chars_before": len(online),
        "online_sha1_before": sha1(online),
        "changed": online != local,
        "backup": "",
        "saved_at": "",
    }
    if online == local and not force:
        result["message"] = "线上已是最新，未写入"
        return result

    if online:
        result["backup"] = backup(cfg, online)

    opener = login(cfg, new_session())
    fields = {
        "page_id": str(cfg["page_id"]),
        "item_id": str(cfg.get("item_id", "")),
        "cat_id": str(cfg.get("cat_id", "")),
        "page_title": cfg["title"] or online_info.get("page_title", ""),
        "is_urlencode": SAVE_URLENCODED,
        "page_content": urllib.parse.quote(local, safe=""),
    }
    call(opener, cfg, "/api/page/save", fields)

    after = call(opener, cfg, "/api/page/info&page_id=%s" % cfg["page_id"])
    saved = after.get("page_content", "")
    if saved != local:
        raise SyncError("写入后回读不一致：线上 %d 字符 sha1=%s，本地 %d 字符 sha1=%s"
                        % (len(saved), sha1(saved)[:12], len(local), sha1(local)[:12]))
    result["online_chars_after"] = len(saved)
    result["online_sha1_after"] = sha1(saved)
    result["saved_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    result["message"] = "同步成功，回读校验一致"
    return result


def do_status():
    cfg = CONFIG
    local = local_text()
    info = fetch_online(cfg)
    online = info.get("page_content", "")
    return {
        "ok": True,
        "page_id": cfg["page_id"],
        "title": info.get("page_title", ""),
        "local_chars": len(local),
        "local_sha1": sha1(local),
        "online_chars": len(online),
        "online_sha1": sha1(online),
        "same": online == local,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "taa-showdoc-sync"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (time.strftime("%H:%M:%S"), fmt % args))

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _same_origin(self):
        """Reject cross-origin writes: the server can publish to ShowDoc."""
        origin = self.headers.get("Origin") or ""
        if not origin:
            return True  # curl / non-browser clients
        host = self.headers.get("Host", "")
        return origin in ("http://%s" % host, "https://%s" % host)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            if path in ("/", "/index.html", "/api-design.html"):
                return self._send(200, VIEW_FILE.read_bytes(), "text/html; charset=utf-8")
            if path == "/api-design.md":
                return self._send(200, PAGE_FILE.read_bytes(), "text/markdown; charset=utf-8")
            if path == "/api/status":
                return self._send_json(200, do_status())
            if path == "/api/config":
                return self._send_json(200, {
                    "page_id": CONFIG["page_id"],
                    "title": CONFIG["title"],
                    "config_path": CONFIG["_path"],
                })
            return self._send_json(404, {"ok": False, "error": "not found"})
        except SyncError as exc:
            return self._send_json(502, {"ok": False, "error": str(exc)})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if not self._same_origin():
            return self._send_json(403, {"ok": False, "error": "cross-origin request rejected"})
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        params = urllib.parse.parse_qs(body)
        force = params.get("force", ["0"])[0] in ("1", "true", "yes")
        try:
            if path == "/api/sync":
                return self._send_json(200, do_sync(force=force))
            return self._send_json(404, {"ok": False, "error": "not found"})
        except SyncError as exc:
            return self._send_json(502, {"ok": False, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - surface any failure to the page
            return self._send_json(500, {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)})


CONFIG = {}


def main():
    global CONFIG
    ap = argparse.ArgumentParser(description="Preview docs/api-design.md and sync it to ShowDoc.")
    ap.add_argument("--port", type=int, default=8770)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--config", help="path to the ShowDoc config JSON")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    CONFIG = load_config(args.config)
    if not PAGE_FILE.exists():
        raise SystemExit("missing %s" % PAGE_FILE)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = "http://%s:%d/" % (args.host, args.port)
    print("serving %s -> %s" % (DOCS, url))
    print("sync target: page %s (%s) via %s" % (CONFIG["page_id"], CONFIG["title"], CONFIG["base"]))
    print("config: %s" % CONFIG["_path"])
    if not args.no_browser:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
