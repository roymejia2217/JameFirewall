#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo ">>> INICIANDO QUALITY GATE VERIFICATION: JAMEFIREWALL <<<"
echo "=========================================================="

echo "[1/6] Comprobando Formato y Linters con Ruff..."
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts

echo "[2/6] Comprobando Tipado Estático Estricto con Mypy..."
uv run mypy src tests scripts

echo "[3/6] Ejecutando Suite de Pruebas Multiplataforma con Pytest y Cobertura..."
uv run pytest --cov=src/jame_firewall --cov-branch --cov-report=term-missing

echo "[4/6] Verificando Ausencia de Nombres Heredados en src/..."
if grep -rnI -E "class AdobeFirewallManager|APP_TITLE = \"Firewall Manager\"" src/; then
    echo "ERROR: Se encontraron referencias de marca obsoleta en src/."
    exit 1
fi

echo "[5/6] Verificando Commitlint y Gobernanza de Commits..."
npm ci --ignore-scripts --no-audit --no-fund > /dev/null
npm run test:commitlint > /dev/null
npm run test:release-please-body > /dev/null
bash scripts/test-commit-range.sh > /dev/null

echo "[6/6] Verificando Towncrier y Gobernanza del Changelog..."
bash scripts/test-changelog-governance.sh > /dev/null
uv run python scripts/validate_release_changelog.py --self-test
uv run python scripts/validate_release_changelog.py

echo "=========================================================="
echo ">>> QUALITY GATE SCORECARD: 100% APROBADO (RELEASE READY) <<<"
echo "=========================================================="
