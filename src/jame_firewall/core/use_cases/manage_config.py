"""Caso de uso para la administración y auto-detección de directorios de búsqueda."""

import os
from pathlib import Path

from jame_firewall.core.ports import (
    ConfigRepositoryPort,
    DirectoryScannerPort,
    RegistryDiscoveryPort,
)


class ManageConfigDirectoriesUseCase:
    """Gestiona la lista persistente de directorios y el auto-descubrimiento."""

    def __init__(
        self,
        config_repo: ConfigRepositoryPort,
        registry: RegistryDiscoveryPort,
        scanner: DirectoryScannerPort,
    ) -> None:
        self._config_repo = config_repo
        self._registry = registry
        self._scanner = scanner
        self._directories: list[Path] = self._config_repo.load_paths()

    def get_directories(self) -> list[Path]:
        """Devuelve una copia de los directorios actualmente configurados."""
        return list(self._directories)

    def add_directory(self, path: Path) -> bool:
        """Añade un nuevo directorio si no existe previamente."""
        resolved = Path(os.path.abspath(path))
        if resolved not in self._directories:
            return self.replace_directories([*self._directories, resolved])
        return False

    def remove_directory(self, path: Path) -> bool:
        """Elimina un directorio de la lista de configuración."""
        resolved = Path(os.path.abspath(path))
        # Buscar por coincidencia exacta o resuelta
        for d in list(self._directories):
            if Path(os.path.abspath(d)) == resolved:
                return self.replace_directories([item for item in self._directories if item != d])
        return False

    def replace_directories(self, paths: list[Path]) -> bool:
        """Commit one complete list; publish it in memory only after storage succeeds."""
        try:
            candidate = list(dict.fromkeys(Path(os.path.abspath(path)) for path in paths))
        except (OSError, ValueError):
            return False
        if not self._config_repo.save_paths(candidate):
            return False
        self._directories = candidate
        return True

    def discover_directories(self, paths: list[Path]) -> list[Path]:
        """Return discovery merged into a draft without changing saved state."""
        result = list(dict.fromkeys(Path(os.path.abspath(path)) for path in paths))
        discovered = self._registry.discover_creative_paths()
        if not discovered:
            return result

        # Podar candidatos redundantes
        pruned_candidates = self._scanner.prune_redundant_paths(discovered)

        for candidate in pruned_candidates:
            # Comprobar si el candidato es subdirectorio de alguno existente
            is_redundant_with_existing = False
            for existing in result:
                try:
                    candidate.relative_to(existing)
                    is_redundant_with_existing = True
                    break
                except ValueError:
                    continue

            if not is_redundant_with_existing and candidate not in result:
                result.append(candidate)
        return result

    def auto_detect(self) -> int:
        """Persist discovered paths only if the whole replacement succeeds."""
        candidate = self.discover_directories(self._directories)
        added_count = len(candidate) - len(self._directories)
        if added_count and self.replace_directories(candidate):
            return added_count
        return 0
