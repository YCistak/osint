#!/usr/bin/env bash
# osint-tui başlatıcı: sanal ortamı (.venv) kurar/kullanır ve uygulamayı açar.
set -e
cd "$(dirname "$(readlink -f "$0")")"

if [ ! -x .venv/bin/osint-tui ]; then
    echo "İlk kurulum yapılıyor (.venv)…"
    if command -v uv >/dev/null 2>&1; then
        uv venv .venv
        uv pip install --python .venv/bin/python -e .
    else
        python3 -m venv .venv
        .venv/bin/pip install -e .
    fi
fi

exec .venv/bin/osint-tui "$@"
