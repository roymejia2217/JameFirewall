"""Stage an immutable Windows release candidate under canonical asset names."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
from pathlib import Path

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


class StagingError(ValueError):
    """Raised when release candidate identity cannot be proven."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_declared_hash(path: Path) -> tuple[str, str]:
    try:
        line = path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise StagingError(f"missing checksum manifest: {path}") from exc
    parts = line.split()
    if len(parts) != 2:
        raise StagingError("checksum manifest must contain hash and filename")
    return parts[0].lower(), parts[1]


def stage(candidate_root: Path, expected_sha256: str, release_version: str) -> Path:
    expected = expected_sha256.lower()
    if not SHA256_RE.fullmatch(expected):
        raise StagingError("expected SHA-256 must be 64 lowercase hexadecimal characters")
    if not VERSION_RE.fullmatch(release_version):
        raise StagingError("release version must be canonical SemVer")

    source = candidate_root / "dist" / "JameFirewall.exe"
    manifest = candidate_root / "dist" / "JameFirewall.exe.sha256"
    if not source.is_file():
        raise StagingError("missing verified candidate: dist/JameFirewall.exe")

    declared, declared_name = _parse_declared_hash(manifest)
    if declared_name != "JameFirewall.exe":
        raise StagingError("checksum manifest filename is not JameFirewall.exe")
    if declared != expected:
        raise StagingError("SHA-256 mismatch: checksum manifest differs from preflight")

    actual = _sha256(source)
    if actual != expected:
        raise StagingError(f"SHA-256 mismatch: expected {expected}, got {actual}")

    canonical_name = f"JameFirewall-v{release_version}-windows-x64.exe"
    canonical = candidate_root / canonical_name
    checksum = candidate_root / f"{canonical_name}.sha256"
    if canonical.exists() or checksum.exists():
        raise StagingError("canonical release asset already exists in staging directory")

    shutil.copy2(source, canonical)
    checksum.write_text(f"{actual}  {canonical_name}\n", encoding="ascii")
    return canonical


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--release-version", required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        canonical = stage(
            args.candidate_root,
            args.expected_sha256,
            args.release_version,
        )
    except StagingError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(canonical.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
