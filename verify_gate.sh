#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo ">>> INICIANDO QUALITY GATE VERIFICATION: JAMEFIREWALL <<<"
echo "=========================================================="

echo "[1/5] Comprobando Formato y Linters con Ruff..."
uv run ruff check src tests
uv run ruff format --check src tests

echo "[2/5] Comprobando Tipado Estático Estricto con Mypy..."
uv run mypy src tests

echo "[3/5] Ejecutando Suite de Pruebas Multiplataforma con Pytest y Cobertura..."
uv run pytest --cov=src/jame_firewall --cov-branch --cov-report=term-missing

echo "[4/5] Verificando Ausencia de Nombres Heredados en src/..."
if grep -rnI -E "class AdobeFirewallManager|APP_TITLE = \"Firewall Manager\"" src/; then
    echo "ERROR: Se encontraron referencias de marca obsoleta en src/."
    exit 1
fi

echo "[5/5] Verificando Motor de Commitlint y Gobernanza de Commits..."
commit_msg_file="$(git rev-parse --git-path COMMIT_EDITMSG)"
backup_file="$(mktemp)"
had_commit_msg=0
if [ -f "$commit_msg_file" ]; then
    cp "$commit_msg_file" "$backup_file"
    had_commit_msg=1
fi
cleanup_commit_msg() {
    if [ "$had_commit_msg" -eq 1 ]; then
        cp "$backup_file" "$commit_msg_file"
    else
        rm -f "$commit_msg_file"
    fi
    rm -f "$backup_file"
}
trap cleanup_commit_msg EXIT
printf '%s\n' "ci(ci): verify commitlint contract" > "$commit_msg_file"
uv run pre-commit run commitlint --hook-stage commit-msg --commit-msg-filename "$commit_msg_file" > /dev/null

echo "=========================================================="
echo ">>> QUALITY GATE SCORECARD: 100% APROBADO (RELEASE READY) <<<"
echo "=========================================================="
