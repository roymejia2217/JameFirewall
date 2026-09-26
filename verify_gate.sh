#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo ">>> INICIANDO QUALITY GATE VERIFICATION: JAMEFIREWALL <<<"
echo "=========================================================="

echo "[1/4] Comprobando Formato y Linters con Ruff..."
/home/roy/.local/bin/uv run ruff check src tests
/home/roy/.local/bin/uv run ruff format --check src tests

echo "[2/4] Comprobando Tipado Estático Estricto con Mypy..."
/home/roy/.local/bin/uv run mypy src tests

echo "[3/4] Ejecutando Suite de Pruebas Multiplataforma con Pytest y Cobertura..."
/home/roy/.local/bin/uv run pytest --cov=src/jame_firewall --cov-branch --cov-report=term-missing

echo "[4/5] Verificando Ausencia de Nombres Heredados en src/..."
if grep -rnI -E "class AdobeFirewallManager|APP_TITLE = \"Firewall Manager\"" src/; then
    echo "ERROR: Se encontraron referencias de marca obsoleta en src/."
    exit 1
fi

echo "[5/5] Verificando Motor de Commitlint y Gobernanza de Commits..."
/home/roy/.local/bin/uv run pre-commit run commitlint --hook-stage commit-msg --commit-msg-filename .git/COMMIT_EDITMSG > /dev/null

echo "=========================================================="
echo ">>> QUALITY GATE SCORECARD: 100% APROBADO (RELEASE READY) <<<"
echo "=========================================================="
