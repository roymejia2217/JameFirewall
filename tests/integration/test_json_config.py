"""Pruebas de integración para persistencia JSON con sustitución portable de variables de entorno."""

import json
import os
from pathlib import Path

import pytest

from jame_firewall.core.exceptions import ConfigStorageError
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


@pytest.mark.parametrize(
    "content",
    [
        "{",
        "[]",
        "null",
        '{"directories": "bad"}',
        '{"directories": [1]}',
        '{"directories": ["relative"]}',
        '{"directories": ["%UNKNOWN_CONFIG_ROOT%/app"]}',
        '{"directories": [], "unexpected": true}',
        '{"directories": ["\\u0000"]}',
    ],
)
def test_invalid_config_is_reported_without_replacing_original(
    tmp_path: Path, content: str
) -> None:
    config = tmp_path / "config.json"
    config.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigStorageError):
        JsonConfigAdapter(config).load_paths()
    assert config.read_text(encoding="utf-8") == content


def test_empty_config_is_intentional(tmp_path: Path) -> None:
    adapter = JsonConfigAdapter(tmp_path / "config.json")
    assert adapter.save_paths([])
    assert adapter.load_paths() == []


@pytest.mark.parametrize("failure", ["replace", "fsync"])
def test_failed_save_preserves_complete_previous_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    config = tmp_path / "config.json"
    adapter = JsonConfigAdapter(config)
    old = tmp_path / "old"
    assert adapter.save_paths([old])
    previous = config.read_bytes()

    def fail(*args: object, **kwargs: object) -> None:
        raise OSError("injected storage failure")

    monkeypatch.setattr(os, failure, fail)
    assert not adapter.save_paths([tmp_path / "new"])
    assert config.read_bytes() == previous
    assert adapter.load_paths() == [old.resolve()]
    assert list(tmp_path.iterdir()) == [config]


def test_file_size_and_directory_count_are_bounded(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(ConfigStorageError):
        JsonConfigAdapter(config).load_paths()
    config.write_text(json.dumps({"directories": [str(tmp_path)] * 257}), encoding="utf-8")
    with pytest.raises(ConfigStorageError):
        JsonConfigAdapter(config).load_paths()


def test_invalid_utf8_is_reported(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_bytes(b"\xff")
    with pytest.raises(ConfigStorageError):
        JsonConfigAdapter(config).load_paths()


def test_environment_root_must_match_path_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "apps"
    monkeypatch.setenv("ProgramFiles", str(root))
    sibling = tmp_path / "apps-other" / "Suite"
    adapter = JsonConfigAdapter(tmp_path / "config.json")
    assert adapter.save_paths([sibling])
    assert adapter.load_paths() == [sibling.resolve()]


def test_repeated_environment_tokens_expand_once_per_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"directories": ["%programfiles%/Suite"]}), encoding="utf-8")
    assert JsonConfigAdapter(config).load_paths() == [(tmp_path / "Suite").resolve()]


def test_symlink_config_is_rejected_without_touching_target(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text('{"directories": []}', encoding="utf-8")
    link = tmp_path / "config.json"
    link.symlink_to(target)
    with pytest.raises(ConfigStorageError):
        JsonConfigAdapter(link).load_paths()
    assert not JsonConfigAdapter(link).save_paths([tmp_path])
    assert target.read_text(encoding="utf-8") == '{"directories": []}'
