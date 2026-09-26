"""Doble de prueba en memoria para ConfigRepositoryPort."""

from pathlib import Path


class MemoryConfigAdapter:
    """Implementación de persistencia de configuración en memoria."""

    def __init__(self, initial_paths: list[Path] | None = None) -> None:
        self.paths: list[Path] = list(initial_paths) if initial_paths else []
        self.should_fail: bool = False

    def load_paths(self) -> list[Path]:
        return list(self.paths)

    def save_paths(self, paths: list[Path]) -> bool:
        if self.should_fail:
            return False
        self.paths = list(paths)
        return True
