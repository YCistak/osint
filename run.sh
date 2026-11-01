#!/usr/bin/env bash
# osint launcher: creates/uses the .venv virtual environment and starts the tool.
set -e
cd "$(dirname "$(readlink -f "$0")")"

if [ ! -x .venv/bin/osint ]; then
    echo "[*] First run: setting up .venv ..."
    if command -v uv >/dev/null 2>&1; then
        uv venv .venv
        uv pip install --python .venv/bin/python -e .
    else
        python3 -m venv .venv
        .venv/bin/pip install -e .
    fi
fi

exec .venv/bin/osint "$@"
