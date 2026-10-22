#!/usr/bin/env bash
# Bootstrap a local venv (PyMySQL is not installed on the host) and run the tool.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
venv="$here/.venv"

if [[ ! -x "$venv/bin/python" ]]; then
    echo "Creating venv in $venv ..." >&2
    python3 -m venv "$venv"
    "$venv/bin/python" -m pip install --quiet --upgrade pip >/dev/null
    "$venv/bin/python" -m pip install --quiet 'pymysql>=1.1'
fi

exec "$venv/bin/python" "$here/bind_image.py" "$@"
