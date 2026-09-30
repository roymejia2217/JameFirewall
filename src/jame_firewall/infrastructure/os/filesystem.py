"""Adaptador de sistema de archivos para escaneo y poda algorítmica."""

import os
from pathlib import Path

from jame_firewall.core.cancellation import CancellationToken


class OSFileSystemAdapter:
    """Implementación de DirectoryScannerPort con poda de subdirectorios redundantes."""

    def __init__(self, cancellation: CancellationToken | None = None) -> None:
        self._cancellation = cancellation or CancellationToken()

    def prune_redundant_paths(self, candidates: list[Path]) -> list[Path]:
        """Elimina rutas hijas si un directorio padre ya se encuentra en la lista."""
        self._cancellation.check()
        resolved: list[Path] = []
        for path in candidates:
            self._cancellation.check()
            resolved.append(path.resolve())
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

    def find_executables(self, search_roots: list[Path]) -> list[Path]:
        """Escanea recursivamente las raíces buscando archivos binarios .exe."""
        pruned_roots = self.prune_redundant_paths(search_roots)
        discovered_executables: list[Path] = []

        for root_path in pruned_roots:
            self._cancellation.check()
            if not root_path.exists() or not root_path.is_dir():
                continue

            try:
                for root, _, files in os.walk(root_path):
                    self._cancellation.check()
                    for file in files:
                        self._cancellation.check()
                        if file.lower().endswith(".exe"):
                            discovered_executables.append(Path(root) / file)
            except OSError:
                continue

        return sorted(discovered_executables)
