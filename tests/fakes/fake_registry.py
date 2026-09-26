"""Doble de prueba en memoria para RegistryDiscoveryPort."""

from pathlib import Path


class FakeRegistryAdapter:
    """Implementación simulada de búsqueda en registro para pruebas."""

    def __init__(self, paths: list[Path] | None = None) -> None:
        self.discovered_paths: list[Path] = paths or []

    def discover_creative_paths(self) -> list[Path]:
        return list(self.discovered_paths)

    def set_discovered_paths(self, paths: list[Path]) -> None:
        self.discovered_paths = list(paths)
