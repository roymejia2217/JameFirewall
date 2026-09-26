"""Pruebas unitarias para ManageConfigDirectoriesUseCase."""

from pathlib import Path

from tests.fakes.fake_config import MemoryConfigAdapter
from tests.fakes.fake_registry import FakeRegistryAdapter

from jame_firewall.core.use_cases.manage_config import ManageConfigDirectoriesUseCase
from jame_firewall.infrastructure.os.filesystem import OSFileSystemAdapter


def test_manage_config_add_remove() -> None:
    repo = MemoryConfigAdapter(initial_paths=[Path("/app/one")])
    reg = FakeRegistryAdapter()
    scanner = OSFileSystemAdapter()

    use_case = ManageConfigDirectoriesUseCase(config_repo=repo, registry=reg, scanner=scanner)

    # Agregar
    added = use_case.add_directory(Path("/app/two"))
    assert added is True
    assert Path("/app/two") in use_case.get_directories()

    # Remover
    removed = use_case.remove_directory(Path("/app/one"))
    assert removed is True
    assert Path("/app/one") not in use_case.get_directories()


def test_manage_config_auto_detect_prunes_redundancies() -> None:
    repo = MemoryConfigAdapter(initial_paths=[Path("/app/Adobe")])
    reg = FakeRegistryAdapter(
        paths=[
            Path("/app/Adobe/Photoshop"),  # Redundante con /app/Adobe
            Path("/app/Common Files/Adobe"),  # Válido nuevo
        ]
    )
    scanner = OSFileSystemAdapter()

    use_case = ManageConfigDirectoriesUseCase(config_repo=repo, registry=reg, scanner=scanner)
    new_count = use_case.auto_detect()

    assert new_count == 1
    dirs = use_case.get_directories()
    assert Path("/app/Common Files/Adobe") in dirs
    assert Path("/app/Adobe/Photoshop") not in dirs
