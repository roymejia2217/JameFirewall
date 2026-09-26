"""Adaptador de sistema de archivos para escaneo y poda algorítmica."""

import os
from pathlib import Path


class OSFileSystemAdapter:
    """Implementación de DirectoryScannerPort con poda de subdirectorios redundantes."""

    def prune_redundant_paths(self, candidates: list[Path]) -> list[Path]:
        """Elimina rutas hijas si un directorio padre ya se encuentra en la lista."""
        normalized = sorted([p.resolve() for p in candidates], key=lambda p: len(str(p)))
        kept_paths: list[Path] = []

        for candidate in normalized:
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
            if not root_path.exists() or not root_path.is_dir():
                continue

            try:
                for root, _, files in os.walk(root_path):
                    for file in files:
                        if file.lower().endswith(".exe"):
                            discovered_executables.append(Path(root) / file)
            except OSError:
                continue

        return sorted(discovered_executables)
