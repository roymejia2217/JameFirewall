"""Adaptador de sistema de archivos para escaneo y poda algorítmica."""

import ctypes
import math
import os
import stat
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from itertools import chain
from pathlib import Path

from jame_firewall.core.cancellation import CancellationToken
from jame_firewall.core.entities import ScanIssue, ScanResult
from jame_firewall.core.execution import check_operation_budget


@dataclass(frozen=True)
class ScanLimits:
    max_roots: int = 256
    max_directories: int = 10_000
    max_entries: int = 200_000
    max_executables: int = 10_000
    max_retained_chars: int = 2_000_000
    max_issues: int = 100
    max_seconds: float = 60.0

    def __post_init__(self) -> None:
        counts = (
            self.max_roots,
            self.max_directories,
            self.max_entries,
            self.max_executables,
            self.max_issues,
            self.max_retained_chars,
        )
        if (
            any(value <= 0 for value in counts)
            or not math.isfinite(self.max_seconds)
            or self.max_seconds <= 0
        ):
            raise ValueError("Scan limits must be positive and finite")


class _ScanStopped(Exception):
    """Internal control flow after a recorded resource limit."""


class OSFileSystemAdapter:
    """Implementación de DirectoryScannerPort con poda de subdirectorios redundantes."""

    def __init__(
        self,
        cancellation: CancellationToken | None = None,
        *,
        limits: ScanLimits | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._cancellation = cancellation or CancellationToken()
        self._limits = limits or ScanLimits()
        self._clock = clock

    def prune_redundant_paths(self, candidates: list[Path]) -> list[Path]:
        """Elimina rutas hijas si un directorio padre ya se encuentra en la lista."""
        self._cancellation.check()
        resolved: list[Path] = []
        for path in candidates:
            self._cancellation.check()
            # Preserve links for traversal validation instead of resolving them into new roots.
            resolved.append(Path(os.path.abspath(path)))
        normalized = sorted(resolved, key=lambda p: len(str(p)))
        kept_paths: list[Path] = []

        for candidate in normalized:
            self._cancellation.check()
            is_redundant = False
            for parent in kept_paths:
                try:
                    candidate.relative_to(parent)
                    is_redundant = True
                    break
                except ValueError:
                    continue

            if not is_redundant:
                kept_paths.append(candidate)

        return kept_paths

    @staticmethod
    def _is_link(info: os.stat_result) -> bool:
        return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)

    @staticmethod
    def _is_remote(path: Path) -> bool:
        if str(path).startswith(("\\\\", "//")):
            return True
        if sys.platform == "win32":
            loader = getattr(ctypes, "WinDLL", None)
            if loader is None:
                raise OSError("Windows drive API is unavailable")
            drive_type = loader("kernel32", use_last_error=True, winmode=0x800).GetDriveTypeW
            drive_type.argtypes, drive_type.restype = [ctypes.c_wchar_p], ctypes.c_uint32
            return bool(drive_type(path.anchor) == 4)  # DRIVE_REMOTE
        return False

    def find_executables(self, search_roots: list[Path]) -> ScanResult:
        """Stream directory entries with finite budgets and explicit scope omissions."""
        start = self._clock()
        limits = self._limits
        issues: list[ScanIssue] = []
        found: dict[str, Path] = {}
        seen_directories: set[tuple[int, int]] = set()
        directory_count = entry_count = retained_chars = 0

        def issue(path: Path, reason: str) -> None:
            issues.append(ScanIssue(Path(str(path)[:512]), reason))
            if len(issues) >= limits.max_issues:
                raise _ScanStopped

        def stop(path: Path, reason: str) -> None:
            issue(path, reason)
            raise _ScanStopped

        def reserve(path: Path, copies: int = 1) -> None:
            nonlocal retained_chars
            size = copies * len(str(path))
            if retained_chars + size > limits.max_retained_chars:
                stop(path, "Límite de memoria de rutas alcanzado")
            retained_chars += size

        def check(path: Path) -> None:
            self._cancellation.check()
            check_operation_budget()
            if self._clock() - start >= limits.max_seconds:
                stop(path, "Límite de duración alcanzado")

        try:
            check(Path("."))
            if len(search_roots) > limits.max_roots:
                stop(Path("."), "Límite de raíces alcanzado")
            pending: list[Path] = []
            # Validate every configured root before pruning overlaps: a missing child
            # must remain an omission even when its existing parent is also configured.
            for configured in search_roots:
                path = Path(os.path.abspath(configured))
                check(path)
                try:
                    if self._is_remote(path):
                        issue(path, "Ruta de red no admitida")
                        continue
                    linked = False
                    for component in chain((path,), path.parents):
                        check(component)
                        if self._is_link(component.lstat()):
                            linked = True
                            break
                    if linked:
                        issue(path, "Enlace o punto de reanálisis omitido")
                    elif not stat.S_ISDIR(path.lstat().st_mode):
                        issue(path, "La raíz no es una carpeta")
                    else:
                        reserve(path)
                        pending.append(path)
                except (OSError, ValueError) as ex:
                    issue(path, f"Raíz inaccesible ({type(ex).__name__})")
            pending = self.prune_redundant_paths(pending)
            retained_chars = sum(len(str(path)) for path in pending)
            pending.reverse()
            while pending:
                path = pending.pop()
                retained_chars -= len(str(path))
                check(path)
                if directory_count >= limits.max_directories:
                    stop(path, "Límite de carpetas alcanzado")
                try:
                    info = path.lstat()
                    if self._is_link(info) or not stat.S_ISDIR(info.st_mode):
                        issue(path, "Carpeta cambiada o punto de reanálisis omitido")
                        continue
                    identity = (info.st_dev, info.st_ino)
                    if info.st_ino and identity in seen_directories:
                        issue(path, "Carpeta repetida omitida")
                        continue
                    seen_directories.add(identity)
                    directory_count += 1
                    with os.scandir(path) as entries:
                        while True:
                            check(path)
                            entry = next(entries, None)
                            if entry is None:
                                break
                            check(path)
                            if entry_count >= limits.max_entries:
                                stop(path, "Límite de entradas alcanzado")
                            entry_count += 1
                            child = Path(entry.path)
                            try:
                                info = entry.stat(follow_symlinks=False)
                                check(child)
                                if self._is_link(info):
                                    issue(child, "Enlace o punto de reanálisis omitido")
                                elif stat.S_ISDIR(info.st_mode):
                                    if directory_count + len(pending) >= limits.max_directories:
                                        stop(child, "Límite de carpetas alcanzado")
                                    reserve(child)
                                    pending.append(child)
                                elif entry.name.lower().endswith(".exe"):
                                    if not stat.S_ISREG(info.st_mode):
                                        issue(child, "El ejecutable no es un archivo regular")
                                        continue
                                    key = os.path.normcase(str(child))
                                    if key not in found and len(found) >= limits.max_executables:
                                        stop(child, "Límite de ejecutables alcanzado")
                                    if key not in found:
                                        reserve(child, copies=2)
                                        found[key] = child
                            except (OSError, ValueError) as ex:
                                issue(child, f"Entrada inaccesible ({type(ex).__name__})")
                except (OSError, ValueError) as ex:
                    issue(path, f"Carpeta inaccesible ({type(ex).__name__})")
        except _ScanStopped:
            pass
        return ScanResult(
            tuple(sorted(found.values())), tuple(issues), directory_count, entry_count
        )
