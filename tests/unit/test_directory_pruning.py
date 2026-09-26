"""Pruebas unitarias para el algoritmo de poda de subdirectorios redundantes."""

from pathlib import Path

from jame_firewall.infrastructure.os.filesystem import OSFileSystemAdapter


def test_prune_redundant_child_paths() -> None:
    scanner = OSFileSystemAdapter()
    candidates = [
        Path("/app/Adobe"),
        Path("/app/Adobe/Photoshop"),
        Path("/app/Adobe/Common Files"),
        Path("/app/Cinema4D"),
        Path("/app/Adobe/Photoshop/Helpers"),
    ]
    pruned = scanner.prune_redundant_paths(candidates)

    assert len(pruned) == 2
    assert Path("/app/Adobe") in pruned
    assert Path("/app/Cinema4D") in pruned
    assert Path("/app/Adobe/Photoshop") not in pruned


def test_find_executables_in_directory_tree(tmp_path: Path) -> None:
    scanner = OSFileSystemAdapter()

    # Crear estructura de prueba
    app_dir = tmp_path / "App"
    app_dir.mkdir()
    (app_dir / "main.exe").touch()
    (app_dir / "helper.EXE").touch()  # Case-insensitive
    (app_dir / "readme.txt").touch()

    sub_dir = app_dir / "sub"
    sub_dir.mkdir()
    (sub_dir / "child.exe").touch()
    (sub_dir / "lib.dll").touch()

    exes = scanner.find_executables([app_dir])
    names = {f.name.lower() for f in exes}

    assert len(exes) == 3
    assert names == {"main.exe", "helper.exe", "child.exe"}
