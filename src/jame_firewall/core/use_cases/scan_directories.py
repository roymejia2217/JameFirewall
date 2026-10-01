"""Caso de uso para escaneo y filtrado algorítmico de rutas."""

from pathlib import Path

from jame_firewall.core.entities import ScanResult
from jame_firewall.core.ports import DirectoryScannerPort


class ScanAndPruneDirectoriesUseCase:
    """Orquesta la normalización y poda de directorios de búsqueda."""

    def __init__(self, scanner: DirectoryScannerPort) -> None:
        self._scanner = scanner

    def execute(self, candidates: list[Path]) -> list[Path]:
        """Elimina subdirectorios redundantes."""
        return self._scanner.prune_redundant_paths(candidates)

    def find_all_executables(self, search_roots: list[Path]) -> ScanResult:
        """Localiza todos los binarios .exe en las raíces suministradas."""
        return self._scanner.find_executables(search_roots)
