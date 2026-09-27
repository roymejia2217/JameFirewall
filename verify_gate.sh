#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo ">>> INICIANDO QUALITY GATE VERIFICATION: JAMEFIREWALL <<<"
echo "=========================================================="

echo "[1/5] Comprobando Formato y Linters con Ruff..."
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts

echo "[2/5] Comprobando Tipado Estático Estricto con Mypy..."
uv run mypy src tests scripts

echo "[3/5] Ejecutando Suite de Pruebas Multiplataforma con Pytest y Cobertura..."
uv run pytest --cov=src/jame_firewall --cov-branch --cov-report=term-missing

echo "[4/5] Verificando Ausencia de Nombres Heredados en src/..."
if grep -rnI -E "class AdobeFirewallManager|APP_TITLE = \"Firewall Manager\"" src/; then
    echo "ERROR: Se encontraron referencias de marca obsoleta en src/."
    exit 1
fi

echo "[5/5] Verificando Commitlint y Gobernanza de Commits..."
npm ci --ignore-scripts --no-audit --no-fund > /dev/null
npm run test:commitlint > /dev/null
bash scripts/test-commit-range.sh > /dev/null

echo "=========================================================="
echo ">>> QUALITY GATE SCORECARD: 100% APROBADO (RELEASE READY) <<<"
echo "=========================================================="
