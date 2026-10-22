#!/usr/bin/env python3
"""Publish an image that already exists in the node registry to the CCS platform.

The platform UI only lists images that have a row in its metadata database.  This
tool reads the image manifest from the local registry on the node, discovers the
platform image table, and inserts a new row by cloning an existing working row.
Cloning keeps unknown/NOT NULL columns at values the platform already accepts.

The default mode is a dry run.  Use --apply to write.

Database credentials are read from environment variables:

    CCS_DB_HOST      default 172.16.10.113
    CCS_DB_PORT      default 3306
    CCS_DB_USER      required
    CCS_DB_PASSWORD  optional (empty password is allowed)
    CCS_DB_NAME      optional, auto-discovered when empty
"""

import argparse
import datetime as _dt
import json
import os
import socket
import ssl
import struct
import sys
import urllib.error
import urllib.request
import uuid

try:
    import pymysql
    from pymysql.cursors import DictCursor
except ImportError:  # pragma: no cover - handled by the wrapper script
    sys.stderr.write(
        "PyMySQL is missing. Run ./bind-image.sh (it creates a local venv) "
        "or install it with: python3 -m pip install pymysql\n"
    )
    sys.exit(2)


DEFAULT_REGISTRY = "172.16.10.178:31313"
SYSTEM_SCHEMAS = ("mysql", "information_schema", "performance_schema", "sys")


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def log(msg):
    print(msg, flush=True)


def qi(name):
    """Quote a MySQL identifier."""
    return "`" + name.replace("`", "``") + "`"


def qtable(schema, table):
    return qi(schema) + "." + qi(table)


def norm(name):
    """Normalise a column name for comparisons (snake_case, lower case)."""
    return name.replace("-", "_").lower()


def gen_id():
    """Generate a 32-char lower-case hex id, matching the platform's id shape."""
    return "2c93" + uuid.uuid4().hex[4:]


def is_string_type(data_type):
    return data_type.lower() in (
        "char", "varchar", "tinytext", "text", "mediumtext", "longtext", "enum", "set"
    )


def is_number_type(data_type):
    return data_type.lower() in (
        "tinyint", "smallint", "mediumint", "int", "integer", "bigint",
        "decimal", "numeric", "float", "double", "real"
    )


def is_time_type(data_type):
    return data_type.lower() in ("datetime", "timestamp")


def first_col(cols, candidates):
    """Return the real column name for the first matching candidate."""
    by_norm = {}
    for name in cols:
        by_norm.setdefault(norm(name), name)
    for candidate in candidates:
        if candidate in by_norm:
            return by_norm[candidate]
    return None


# --------------------------------------------------------------------------- #
# Registry access
# --------------------------------------------------------------------------- #

MANIFEST_ACCEPT = ", ".join([
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
])


class Registry:
    def __init__(self, host, insecure=True, cacert=None, username=None, password=None,
                 arch="amd64"):
        self.host = host
        self.arch = arch
        self.username = username
        self.password = password
        if insecure:
            self.ctx = ssl._create_unverified_context()
        else:
            self.ctx = ssl.create_default_context(cafile=cacert)

    def _request(self, path, accept=None):
        url = "https://%s%s" % (self.host, path)
        req = urllib.request.Request(url)
        if accept:
            req.add_header("Accept", accept)
        if self.username:
            import base64
            token = base64.b64encode(
                ("%s:%s" % (self.username, self.password or "")).encode()
            ).decode()
            req.add_header("Authorization", "Basic " + token)
        return urllib.request.urlopen(req, context=self.ctx, timeout=15)

    def get_json(self, path, accept=None):
        with self._request(path, accept) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def catalog(self):
        return self.get_json("/v2/_catalog").get("repositories", [])

    def tags(self, repo):
        return self.get_json("/v2/%s/tags/list" % repo).get("tags") or []

    def manifest(self, repo, tag):
        data = self.get_json("/v2/%s/manifests/%s" % (repo, tag), MANIFEST_ACCEPT)
        media_type = data.get("mediaType", "")
        if "index" in media_type or "list" in media_type:
            chosen = None
            for entry in data.get("manifests", []):
                platform = entry.get("platform") or {}
                if platform.get("architecture") == self.arch and platform.get("os") == "linux":
                    chosen = entry
                    break
            if chosen is None:
                raise SystemExit("Manifest index has no linux/%s entry" % self.arch)
            data = self.get_json(
                "/v2/%s/manifests/%s" % (repo, chosen["digest"]), MANIFEST_ACCEPT
            )
        return data

    def config(self, repo, digest):
        return self.get_json("/v2/%s/blobs/%s" % (repo, digest))

    def image_info(self, repo, tag):
        manifest = self.manifest(repo, tag)
        config_digest = (manifest.get("config") or {}).get("digest", "")
        total = (manifest.get("config") or {}).get("size", 0)
        total += sum(layer.get("size", 0) for layer in manifest.get("layers", []))
        cfg = {}
        if config_digest:
            try:
                cfg = self.config(repo, config_digest)
            except Exception:
                cfg = {}
        return {
            "manifest": manifest,
            "digest": config_digest,
            "size": total,
            "architecture": cfg.get("architecture", self.arch),
            "os": cfg.get("os", "linux"),
            "created": cfg.get("created"),
        }


def parse_image_ref(ref, default_registry):
    """Split an image reference into (registry, repo, tag)."""
    ref = ref.strip()
    if "@" in ref:
        ref = ref.split("@", 1)[0]
    first, sep, rest = ref.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        registry, repo = first, rest
    else:
        registry, repo = default_registry, ref
    repo, _, tag = repo.rpartition(":")
    if not repo:
        repo, tag = tag, "latest"
    if not tag:
        tag = "latest"
    return registry, repo, tag


# --------------------------------------------------------------------------- #
# Database discovery
# --------------------------------------------------------------------------- #

def db_endpoint(args):
    host = args.db_host or os.environ.get("CCS_DB_HOST", "172.16.10.113")
    port = int(args.db_port or os.environ.get("CCS_DB_PORT", "3306"))
    return host, port


def probe_db_version(args):
    """Read the MySQL handshake banner.  This needs no account, but it cannot
    query or write anything: every SQL statement still requires authentication.
    """
    host, port = db_endpoint(args)
    sock = socket.create_connection((host, port), timeout=5)
    try:
        header = sock.recv(4)
        if len(header) < 4:
            raise SystemExit("No MySQL handshake received from %s:%d." % (host, port))
        length = header[0] | (header[1] << 8) | (header[2] << 16)
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        if not data or data[0] != 10:
            raise SystemExit("%s:%d did not answer with a MySQL handshake." % (host, port))
        end = data.index(b"\x00", 1)
        version = data[1:end].decode("utf-8", "replace")
        conn_id = struct.unpack("<I", data[end + 1:end + 5])[0]
    finally:
        sock.close()
    log("MySQL server %s at %s:%d (connection id %d)" % (version, host, port, conn_id))
    log("Handshake is unauthenticated by design; SELECT/INSERT still need an account.")


def connect_db(args):
    user = args.db_user or os.environ.get("CCS_DB_USER")
    if not user:
        raise SystemExit(
            "Set CCS_DB_USER (and optionally CCS_DB_PASSWORD) or pass --db-user."
        )
    password = os.environ.get("CCS_DB_PASSWORD", "")
    host, port = db_endpoint(args)
    return pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=args.db_name or os.environ.get("CCS_DB_NAME") or None,
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=False,
    )


def load_columns(conn, schema, table):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, EXTRA, COLUMN_KEY
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s
            ORDER BY ORDINAL_POSITION
            """,
            (schema, table),
        )
        return {row["COLUMN_NAME"]: row for row in cur.fetchall()}


def find_image_tables(conn, db_name=None):
    """Find tables that look like the platform's image metadata table."""
    where = ["TABLE_SCHEMA NOT IN (%s)" % ",".join(["%s"] * len(SYSTEM_SCHEMAS))]
    params = list(SYSTEM_SCHEMAS)
    if db_name:
        where.append("TABLE_SCHEMA=%s")
        params.append(db_name)
    sql = """
        SELECT TABLE_SCHEMA, TABLE_NAME,
               GROUP_CONCAT(LOWER(COLUMN_NAME) ORDER BY ORDINAL_POSITION) AS cols
        FROM information_schema.COLUMNS
        WHERE {where}
        GROUP BY TABLE_SCHEMA, TABLE_NAME
    """.format(where=" AND ".join(where))
    with conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    found = []
    for row in rows:
        cols = set((row["cols"] or "").split(","))
        has_name = "model_name" in cols
        has_env = "env_type" in cols or "envtype" in cols
        has_flag = "is_enabled" in cols or "enable_dcu" in cols or "is_enabled" in cols
        if has_name and has_env and has_flag:
            found.append((row["TABLE_SCHEMA"], row["TABLE_NAME"], sorted(cols)))
    return found


def find_binding_tables(conn, db_name=None):
    """Find tables that look like a node<->image binding table."""
    where = ["TABLE_SCHEMA NOT IN (%s)" % ",".join(["%s"] * len(SYSTEM_SCHEMAS))]
    params = list(SYSTEM_SCHEMAS)
    if db_name:
        where.append("TABLE_SCHEMA=%s")
        params.append(db_name)
    sql = """
        SELECT TABLE_SCHEMA, TABLE_NAME,
               GROUP_CONCAT(LOWER(COLUMN_NAME) ORDER BY ORDINAL_POSITION) AS cols
        FROM information_schema.COLUMNS
        WHERE {where}
        GROUP BY TABLE_SCHEMA, TABLE_NAME
    """.format(where=" AND ".join(where))
    with conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    found = []
    for row in rows:
        cols = set((row["cols"] or "").split(","))
        if "node_id" not in cols:
            continue
        if cols & {"image_id", "development_model_id", "model_id",
                   "image_name", "image_ref", "image"}:
            found.append((row["TABLE_SCHEMA"], row["TABLE_NAME"], sorted(cols)))
    return found


def default_schema(args, conn):
    if args.db_name:
        return args.db_name
    db = conn.db
    if isinstance(db, bytes):
        db = db.decode()
    if not db:
        raise SystemExit("Pass --db-name (the connection has no default database).")
    return db


def resolve_table(args, conn, candidates, label):
    if args.table:
        schema, _, table = args.table.partition(".")
        if not table:
            schema, table = default_schema(args, conn), schema
        return schema, table
    if args.db_name:
        scoped = [c for c in candidates if c[0] == args.db_name]
        if scoped:
            candidates = scoped
    if len(candidates) == 1:
        return candidates[0][0], candidates[0][1]
    if not candidates:
        raise SystemExit(
            "No candidate %s table found. Pass --table <schema>.<table>." % label
        )
    log("Multiple %s tables found:" % label)
    for schema, table, cols in candidates:
        log("  %s.%s  (%s)" % (schema, table, ",".join(cols)))
    raise SystemExit("Pass --table <schema>.<table> to choose one.")


# --------------------------------------------------------------------------- #
# Row building
# --------------------------------------------------------------------------- #

def fetch_template(conn, schema, table, cols, env_type=None, template_id=None,
                   want_enabled=True):
    filters = []
    params = []
    if template_id:
        id_col = first_col(cols, ["id"])
        if not id_col:
            raise SystemExit("Table has no id column; --template-id is not supported.")
        filters.append("%s=%%s" % qi(id_col))
        params.append(template_id)
    else:
        enabled_col = first_col(cols, ["is_enabled"])
        env_col = first_col(cols, ["env_type", "envtype"])
        if want_enabled and enabled_col:
            filters.append("%s=1" % qi(enabled_col))
        if env_type and env_col:
            filters.append("%s=%%s" % qi(env_col))
            params.append(env_type)
    order_col = first_col(cols, ["update_time", "modified_time", "gmt_modified", "id"])
    order = " ORDER BY %s DESC" % qi(order_col) if order_col else ""
    where = (" WHERE " + " AND ".join(filters)) if filters else ""
    sql = "SELECT * FROM %s%s%s LIMIT 1" % (
        qtable(schema, table), where, order
    )
    with conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
    if row:
        return row
    # Fall back to any row; the caller prints a warning.
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM %s LIMIT 1" % qtable(schema, table))
        return cur.fetchone()


def find_existing(conn, schema, table, cols, model_name, version, env_type):
    name_col = first_col(cols, ["model_name"])
    version_col = first_col(cols, ["version"])
    env_col = first_col(cols, ["env_type", "envtype"])
    id_col = first_col(cols, ["id"])
    if not id_col:
        # Without an id column we cannot address an existing row safely.
        return None
    filters = ["%s=%%s" % qi(name_col)]
    params = [model_name]
    if version_col and is_string_type(cols[version_col]["DATA_TYPE"]):
        filters.append("%s=%%s" % qi(version_col))
        params.append(version)
    if env_col:
        filters.append("%s=%%s" % qi(env_col))
        params.append(env_type)
    sql = "SELECT %s AS id FROM %s WHERE %s LIMIT 1" % (
        qi(id_col),
        qtable(schema, table),
        " AND ".join(filters),
    )
    with conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
    return row["id"] if row else None


def set_col(row, cols, candidates, value):
    col = first_col(cols, candidates)
    if col is not None:
        row[col] = value
        return True
    return False


def build_new_row(template, cols, args, image_ref, repo, tag, info):
    row = dict(template)
    now = _dt.datetime.now().replace(microsecond=0)

    id_col = first_col(cols, ["id"])
    if id_col:
        extra = (cols[id_col]["EXTRA"] or "").lower()
        if "auto_increment" in extra:
            row.pop(id_col, None)
        else:
            row[id_col] = gen_id()

    set_col(row, cols, ["model_name"], args.model_name or repo)
    version_col = first_col(cols, ["version"])
    if version_col and is_string_type(cols[version_col]["DATA_TYPE"]):
        row[version_col] = args.version or tag
    set_col(row, cols, ["env_type", "envtype"], args.env_type)
    set_col(row, cols, ["enable_dcu"], 1 if args.dcu else 0)
    set_col(row, cols, ["is_enabled"], 1)
    set_col(row, cols, ["size"], info["size"])
    set_col(row, cols, ["image_size"], info["size"])
    set_col(row, cols, ["digest", "image_digest"], info["digest"])
    set_col(row, cols, ["image", "image_ref", "image_url"], image_ref)
    set_col(row, cols, ["image_name"], image_ref)
    set_col(row, cols, ["repository", "repo"], repo)
    set_col(row, cols, ["tag", "image_tag"], tag)
    set_col(row, cols, ["arch", "architecture"], info["architecture"])
    set_col(row, cols, ["os"], info["os"])

    if args.model_desc is not None:
        set_col(row, cols, ["model_desc", "description", "remark"], args.model_desc)
    if args.min_cpu is not None:
        set_col(row, cols, ["min_cpu", "min_cpu_number"], args.min_cpu)
    if args.min_memory_g is not None:
        set_col(row, cols, ["min_memory_g", "min_memory"], args.min_memory_g)
    if args.tenant_id is not None:
        set_col(row, cols, ["tenant_id"], args.tenant_id)
    if args.env_region_id is not None:
        set_col(row, cols, ["env_region_id"], args.env_region_id)
    if args.visibility is not None:
        set_col(row, cols, ["visibility"], args.visibility)

    for candidates in (
        ["creation_time", "create_time", "created_at", "gmt_create"],
        ["update_time", "modified_time", "updated_at", "gmt_modified"],
    ):
        col = first_col(cols, candidates)
        if col and is_time_type(cols[col]["DATA_TYPE"]):
            row[col] = now
    return row


def insert_row(conn, schema, table, cols, row, apply=False):
    # Drop generated columns and unknown keys.
    values = {}
    for name, value in row.items():
        if name not in cols:
            continue
        extra = (cols[name]["EXTRA"] or "").lower()
        if "virtual generated" in extra or "stored generated" in extra:
            continue
        values[name] = value
    names = list(values.keys())
    sql = "INSERT INTO %s (%s) VALUES (%s)" % (
        qtable(schema, table),
        ", ".join(qi(n) for n in names),
        ", ".join(["%s"] * len(names)),
    )
    params = [values[n] for n in names]
    log("\nSQL:\n%s" % sql)
    preview = {}
    for name in names:
        value = values[name]
        text = repr(value)
        if len(text) > 80:
            text = text[:77] + "..."
        preview[name] = text
    log("Params: %s" % json.dumps(preview, ensure_ascii=False, indent=2))
    if not apply:
        log("\nDry run: nothing written. Re-run with --apply to insert.")
        return None
    with conn.cursor() as cur:
        cur.execute(sql, params)
        last_id = cur.lastrowid
    conn.commit()
    id_col = first_col(cols, ["id"])
    if id_col and id_col in values:
        return values[id_col]
    return last_id


def make_binding_row(template, cols, node_id, image_id, image_ref):
    row = dict(template)
    id_col = first_col(cols, ["id"])
    if id_col and "auto_increment" not in (cols[id_col]["EXTRA"] or "").lower():
        row[id_col] = gen_id()
    set_col(row, cols, ["node_id"], node_id)
    id_target = first_col(cols, ["image_id", "development_model_id", "model_id"])
    if id_target:
        row[id_target] = image_id
        return row
    set_col(row, cols, ["image_name", "image_ref", "image"], image_ref)
    return row


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def cmd_list(args):
    reg = Registry(
        args.registry, insecure=not args.no_insecure, cacert=args.cacert,
        username=args.registry_user, password=os.environ.get("CCS_REGISTRY_PASSWORD", ""),
    )
    repos = sorted(reg.catalog())
    for repo in repos:
        try:
            tags = reg.tags(repo)
        except Exception as exc:
            log("%s: <tags unavailable: %s>" % (repo, exc))
            continue
        for tag in sorted(tags):
            log("%s:%s" % (repo, tag))


def cmd_insert(args):
    conn = connect_db(args)
    try:
        candidates = find_image_tables(conn, args.db_name)
        schema, table = resolve_table(args, conn, candidates, "image")
        cols = load_columns(conn, schema, table)
        log("Table:  %s.%s" % (schema, table))
        if args.inspect:
            log("\nColumns:")
            for name, meta in cols.items():
                log("  %-28s %-12s null=%s default=%r extra=%s" % (
                    name, meta["DATA_TYPE"], meta["IS_NULLABLE"],
                    meta["COLUMN_DEFAULT"], meta["EXTRA"],
                ))
            binding = find_binding_tables(conn, args.db_name)
            if binding:
                log("\nNode-image binding candidates:")
                for bs, bt, bcols in binding:
                    log("  %s.%s  (%s)" % (bs, bt, ",".join(bcols)))
            return

        if not args.image:
            raise SystemExit("Pass --image (or --inspect).")

        registry, repo, tag = parse_image_ref(args.image, args.registry)
        reg = Registry(
            registry, insecure=not args.no_insecure, cacert=args.cacert,
            username=args.registry_user,
            password=os.environ.get("CCS_REGISTRY_PASSWORD", ""),
            arch=args.arch,
        )
        log("Reading manifest from https://%s/v2/%s/manifests/%s" % (registry, repo, tag))
        info = reg.image_info(repo, tag)
        image_ref = "%s/%s:%s" % (registry, repo, tag)
        log("Image:  %s" % image_ref)
        log("Digest: %s" % info["digest"])
        log("Size:   %d bytes (%.2f GiB)" % (info["size"], info["size"] / 1024.0 ** 3))

        template = fetch_template(
            conn, schema, table, cols,
            env_type=args.env_type, template_id=args.template_id,
        )
        if not template:
            raise SystemExit("No template row found; pass --template-id.")
        id_col = first_col(cols, ["id"])
        log("Template row id=%s" % (template.get(id_col) if id_col else "<none>"))
        if not args.template_id and args.env_type:
            env_col = first_col(cols, ["env_type", "envtype"])
            if env_col and template.get(env_col) != args.env_type:
                log("Warning: template env_type=%r, requested %r" % (
                    template.get(env_col), args.env_type))

        model_name = args.model_name or repo
        version = args.version or tag
        existing = find_existing(
            conn, schema, table, cols, model_name, version, args.env_type
        )
        if existing:
            log("Existing row for %s:%s (%s): id=%s" % (
                model_name, version, args.env_type, existing))
            if not args.update_existing:
                raise SystemExit(
                    "Row already exists. Use --update-existing to update it."
                )
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM %s WHERE %s=%%s" % (
                    qtable(schema, table), qi(id_col)), (existing,))
                base = cur.fetchone()
            row = build_new_row(base, cols, args, image_ref, repo, tag, info)
            row[id_col] = existing if id_col else None
            update_row(conn, schema, table, cols, row, existing, args)
            return

        row = build_new_row(template, cols, args, image_ref, repo, tag, info)
        new_id = insert_row(conn, schema, table, cols, row, apply=args.apply)
        if args.apply:
            log("Inserted image row id=%s" % new_id)

        if args.bind_node:
            bind_node(conn, args, new_id or row.get(id_col), image_ref)

        if args.apply:
            verify(conn, schema, table, cols, new_id or row.get(id_col))
    finally:
        conn.close()


def update_row(conn, schema, table, cols, row, row_id, args):
    id_col = first_col(cols, ["id"])
    assignments = []
    params = []
    for name, value in row.items():
        if name == id_col or name not in cols:
            continue
        extra = (cols[name]["EXTRA"] or "").lower()
        if "virtual generated" in extra or "stored generated" in extra:
            continue
        assignments.append("%s=%%s" % qi(name))
        params.append(value)
    sql = "UPDATE %s SET %s WHERE %s=%%s" % (
        qtable(schema, table), ", ".join(assignments), qi(id_col)
    )
    params.append(row_id)
    log("\nSQL:\n%s" % sql)
    log("Params: %d values" % (len(params) - 1))
    if not args.apply:
        log("\nDry run: nothing written. Re-run with --apply to update.")
        return
    with conn.cursor() as cur:
        cur.execute(sql, params)
    conn.commit()
    log("Updated image row id=%s" % row_id)


def bind_node(conn, args, image_id, image_ref):
    candidates = find_binding_tables(conn, args.db_name)
    if args.bind_table:
        schema, _, table = args.bind_table.partition(".")
        if not table:
            schema, table = default_schema(args, conn), schema
    else:
        schema, table = resolve_table(args, conn, candidates, "node-image binding")
    cols = load_columns(conn, schema, table)
    log("Binding table: %s.%s" % (schema, table))
    node_col = first_col(cols, ["node_id"])
    order_col = first_col(cols, ["id"])
    with conn.cursor() as cur:
        sql = "SELECT * FROM %s WHERE %s=%%s%s LIMIT 1" % (
            qtable(schema, table), qi(node_col),
            (" ORDER BY %s DESC" % qi(order_col)) if order_col else "",
        )
        cur.execute(sql, (args.bind_node,))
        template = cur.fetchone()
    if not template:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM %s LIMIT 1" % qtable(schema, table))
            template = cur.fetchone()
    if not template:
        raise SystemExit("No template row in binding table; cannot clone a binding.")
    row = make_binding_row(template, cols, args.bind_node, image_id, image_ref)
    insert_row(conn, schema, table, cols, row, apply=args.apply)


def verify(conn, schema, table, cols, row_id):
    id_col = first_col(cols, ["id"])
    if not id_col or not row_id:
        return
    keys = [c for c in (
        id_col,
        first_col(cols, ["model_name"]),
        first_col(cols, ["version"]),
        first_col(cols, ["env_type", "envtype"]),
        first_col(cols, ["enable_dcu"]),
        first_col(cols, ["is_enabled"]),
        first_col(cols, ["size"]),
    ) if c]
    sql = "SELECT %s FROM %s WHERE %s=%%s" % (
        ", ".join(qi(k) for k in keys), qtable(schema, table), qi(id_col)
    )
    with conn.cursor() as cur:
        cur.execute(sql, (row_id,))
        log("\nVerify: %s" % json.dumps(cur.fetchone(), default=str, ensure_ascii=False))


def build_parser():
    p = argparse.ArgumentParser(
        description="Insert a registry image into the CCS platform metadata database."
    )
    p.add_argument("--image", help="Image reference, e.g. taa-env:my-tag")
    p.add_argument("--list-images", action="store_true",
                   help="List repositories and tags in the node registry")
    p.add_argument("--inspect", action="store_true",
                   help="Print candidate table columns and exit")
    p.add_argument("--apply", action="store_true", help="Actually write (default: dry run)")
    p.add_argument("--table", help="Image table as schema.table")
    p.add_argument("--template-id", help="Clone this image row instead of auto-selecting")
    p.add_argument("--update-existing", action="store_true",
                   help="Update the row if model_name/version/env_type already exists")
    p.add_argument("--model-name", help="Defaults to the repository name")
    p.add_argument("--version", help="Defaults to the tag")
    p.add_argument("--env-type", default="TEE_INFER_DCU",
                   help="TEE_INFER_CPU, TEE_INFER_DCU, TEE_TRAIN_CPU or FHE_INFER")
    p.add_argument("--dcu", dest="dcu", action="store_true", default=True,
                   help="Set enable_dcu=1 (default)")
    p.add_argument("--no-dcu", dest="dcu", action="store_false", help="Set enable_dcu=0")
    p.add_argument("--tenant-id")
    p.add_argument("--env-region-id")
    p.add_argument("--visibility")
    p.add_argument("--min-cpu", type=int)
    p.add_argument("--min-memory-g", type=int)
    p.add_argument("--model-desc")
    p.add_argument("--bind-node", help="Node id to bind the image to (optional)")
    p.add_argument("--bind-table", help="Node-image binding table as schema.table")
    p.add_argument("--registry", default=DEFAULT_REGISTRY)
    p.add_argument("--arch", default="amd64")
    p.add_argument("--cacert")
    p.add_argument("--no-insecure", action="store_true",
                   help="Verify the registry TLS certificate")
    p.add_argument("--registry-user", help="Registry user (password from CCS_REGISTRY_PASSWORD)")
    p.add_argument("--db-version", action="store_true",
                   help="Print the MySQL handshake version and exit (no account needed)")
    p.add_argument("--db-host")
    p.add_argument("--db-port")
    p.add_argument("--db-user")
    p.add_argument("--db-name")
    return p


def main():
    args = build_parser().parse_args()
    if args.db_version:
        probe_db_version(args)
        return
    if args.list_images:
        cmd_list(args)
        return
    if not args.image and not args.inspect:
        raise SystemExit("Pass --image, --inspect or --list-images. See --help.")
    cmd_insert(args)


if __name__ == "__main__":
    main()
