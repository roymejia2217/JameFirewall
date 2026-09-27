"""Behavioral contracts for staging verified Windows release assets."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/stage_release_assets.py"


def test_stages_dist_candidate_with_verified_identity(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    dist = candidate / "dist"
    dist.mkdir(parents=True)
    payload = b"verified-windows-binary"
    exe = dist / "JameFirewall.exe"
    exe.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    (dist / "JameFirewall.exe.sha256").write_text(f"{digest}  JameFirewall.exe\n", encoding="ascii")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--candidate-root",
            str(candidate),
            "--expected-sha256",
            digest,
            "--release-version",
            "0.2.0",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    canonical = candidate / "JameFirewall-v0.2.0-windows-x64.exe"
    checksum = candidate / "JameFirewall-v0.2.0-windows-x64.exe.sha256"
    assert canonical.read_bytes() == payload
    assert checksum.read_text(encoding="ascii") == (
        f"{digest}  JameFirewall-v0.2.0-windows-x64.exe\n"
    )


def test_rejects_mismatched_preflight_hash(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    dist = candidate / "dist"
    dist.mkdir(parents=True)
    exe = dist / "JameFirewall.exe"
    exe.write_bytes(b"candidate")
    actual = hashlib.sha256(b"candidate").hexdigest()
    (dist / "JameFirewall.exe.sha256").write_text(f"{actual}  JameFirewall.exe\n", encoding="ascii")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--candidate-root",
            str(candidate),
            "--expected-sha256",
            "0" * 64,
            "--release-version",
            "0.2.0",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "SHA-256 mismatch" in result.stderr


def test_rejects_flattened_or_missing_dist_candidate(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "JameFirewall.exe").write_bytes(b"wrong-layout")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--candidate-root",
            str(candidate),
            "--expected-sha256",
            "0" * 64,
            "--release-version",
            "0.2.0",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "dist/JameFirewall.exe" in result.stderr


def test_rejects_tampered_binary_even_when_manifest_matches_expected(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate"
    dist = candidate / "dist"
    dist.mkdir(parents=True)
    expected = hashlib.sha256(b"original").hexdigest()
    (dist / "JameFirewall.exe").write_bytes(b"tampered")
    (dist / "JameFirewall.exe.sha256").write_text(
        f"{expected}  JameFirewall.exe\n", encoding="ascii"
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--candidate-root",
            str(candidate),
            "--expected-sha256",
            expected,
            "--release-version",
            "0.2.0",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "SHA-256 mismatch" in result.stderr


def test_rejects_invalid_release_version(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--candidate-root",
            str(candidate),
            "--expected-sha256",
            "0" * 64,
            "--release-version",
            "../0.2.0",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "canonical SemVer" in result.stderr


def test_rejects_preexisting_canonical_asset(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    dist = candidate / "dist"
    dist.mkdir(parents=True)
    payload = b"verified"
    digest = hashlib.sha256(payload).hexdigest()
    (dist / "JameFirewall.exe").write_bytes(payload)
    (dist / "JameFirewall.exe.sha256").write_text(f"{digest}  JameFirewall.exe\n", encoding="ascii")
    (candidate / "JameFirewall-v0.2.0-windows-x64.exe").write_bytes(b"existing")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--candidate-root",
            str(candidate),
            "--expected-sha256",
            digest,
            "--release-version",
            "0.2.0",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "already exists" in result.stderr
