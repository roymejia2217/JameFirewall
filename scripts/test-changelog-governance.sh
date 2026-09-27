#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cp "$ROOT/pyproject.toml" "$TMP/pyproject.toml"
mkdir -p "$TMP/changelog.d"
cp "$ROOT/changelog.d/towncrier-template.md" "$TMP/changelog.d/"

cat > "$TMP/CHANGELOG.md" <<'EOF'
# Changelog

All notable changes are documented in this file.

The format is based on Keep a Changelog and the project follows Semantic Versioning.

## [Unreleased]

<!-- towncrier release notes start -->

EOF

printf '%s\n' 'Added a public changelog governance fixture.'   > "$TMP/changelog.d/101.added.md"
printf '%s\n' 'This internal fixture must never render publicly.'   > "$TMP/changelog.d/+governance.internal.md"

draft="$(uv run towncrier build --config "$TMP/pyproject.toml" --dir "$TMP" --draft --version 9.9.9 --date 2026-01-02)"

grep -F '### Added' <<< "$draft" >/dev/null
grep -F 'Added a public changelog governance fixture.' <<< "$draft" >/dev/null

if grep -F '### Internal' <<< "$draft" >/dev/null; then
  echo 'Internal Towncrier category leaked into public draft output.' >&2
  exit 1
fi

if grep -F 'This internal fixture must never render publicly.' <<< "$draft" >/dev/null; then
  echo 'Internal Towncrier fragment leaked into public draft output.' >&2
  exit 1
fi

for token in '✨' '🐛' '⚡' '♻️' '📚' '🔧'; do
  if grep -F "$token" <<< "$draft" >/dev/null; then
    echo "Decorative changelog token leaked into Towncrier output: $token" >&2
    exit 1
  fi
done

uv run towncrier build   --config "$TMP/pyproject.toml"   --dir "$TMP"   --yes   --version 9.9.9   --date 2026-01-02 >/dev/null

grep -F   '## [9.9.9](https://github.com/roymejia2217/JameFirewall/releases/tag/v9.9.9) - 2026-01-02'   "$TMP/CHANGELOG.md" >/dev/null

grep -F '### Added' "$TMP/CHANGELOG.md" >/dev/null

if grep -F 'Internal' "$TMP/CHANGELOG.md" >/dev/null; then
  echo 'Internal Towncrier content leaked into generated CHANGELOG.md.' >&2
  exit 1
fi

echo 'Towncrier changelog governance contract: ok'
