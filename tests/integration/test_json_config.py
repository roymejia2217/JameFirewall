"""Pruebas de integración para persistencia JSON con sustitución portable de variables de entorno."""

from pathlib import Path

import pytest

from jame_firewall.infrastructure.persistence.json_config import JsonConfigAdapter


def test_json_config_sanitizes_and_expands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Configurar variable de entorno simulada
    test_root = tmp_path / "ProgramFiles"
    test_root.mkdir()
    monkeypatch.setenv("ProgramFiles", str(test_root))

    config_file = tmp_path / "test_config.json"
    adapter = JsonConfigAdapter(config_path=config_file)

    target_path = test_root / "CreativeSuite" / "App"
    adapter.save_paths([target_path])

    # Verificar que en el JSON se almacenó con %ProgramFiles%
    raw_json = config_file.read_text(encoding="utf-8")
    assert "%ProgramFiles%" in raw_json
    assert str(test_root) not in raw_json

    # Cargar y verificar expansión a ruta real
    loaded = adapter.load_paths()
    assert len(loaded) == 1
    assert loaded[0] == target_path.resolve()


def test_json_config_fallback_to_defaults(tmp_path: Path) -> None:
    non_existent = tmp_path / "empty.json"
    adapter = JsonConfigAdapter(config_path=non_existent)
    paths = adapter.load_paths()
    assert len(paths) > 0  # Carga rutas por defecto si no existe el archivo
