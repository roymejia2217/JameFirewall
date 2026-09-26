"""Caso de uso para la administración y auto-detección de directorios de búsqueda."""

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
        resolved = path.resolve()
        if resolved not in self._directories:
            self._directories.append(resolved)
            return self._config_repo.save_paths(self._directories)
        return False

    def remove_directory(self, path: Path) -> bool:
        """Elimina un directorio de la lista de configuración."""
        resolved = path.resolve()
        # Buscar por coincidencia exacta o resuelta
        for d in list(self._directories):
            if d.resolve() == resolved:
                self._directories.remove(d)
                return self._config_repo.save_paths(self._directories)
        return False

    def auto_detect(self) -> int:
        """Detecta rutas desde el Registro y agrega únicamente las no redundantes."""
        discovered = self._registry.discover_creative_paths()
        if not discovered:
            return 0

        # Podar candidatos redundantes
        pruned_candidates = self._scanner.prune_redundant_paths(discovered)

        added_count = 0
        for candidate in pruned_candidates:
            # Comprobar si el candidato es subdirectorio de alguno existente
            is_redundant_with_existing = False
            for existing in self._directories:
                try:
                    candidate.relative_to(existing)
                    is_redundant_with_existing = True
                    break
                except ValueError:
                    continue

            if not is_redundant_with_existing and candidate not in self._directories:
                self._directories.append(candidate)
                added_count += 1

        if added_count > 0:
            self._config_repo.save_paths(self._directories)

        return added_count
