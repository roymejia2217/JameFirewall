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


class CountingConfigAdapter(MemoryConfigAdapter):
    def __init__(self, initial_paths: list[Path]) -> None:
        super().__init__(initial_paths)
        self.save_attempts: list[list[Path]] = []

    def save_paths(self, paths: list[Path]) -> bool:
        self.save_attempts.append(list(paths))
        return super().save_paths(paths)


def config_use_case(
    repo: MemoryConfigAdapter, discovered: list[Path] | None = None
) -> ManageConfigDirectoriesUseCase:
    return ManageConfigDirectoriesUseCase(
        config_repo=repo,
        registry=FakeRegistryAdapter(paths=discovered),
        scanner=OSFileSystemAdapter(),
    )


def test_failed_add_keeps_memory_and_repository_unchanged(tmp_path: Path) -> None:
    original = [tmp_path / "existing"]
    repo = MemoryConfigAdapter(original)
    use_case = config_use_case(repo)
    repo.should_fail = True

    assert use_case.add_directory(tmp_path / "new") is False
    assert use_case.get_directories() == original
    assert repo.load_paths() == original


def test_failed_remove_keeps_memory_and_repository_unchanged(tmp_path: Path) -> None:
    original = [tmp_path / "existing", tmp_path / "keep"]
    repo = MemoryConfigAdapter(original)
    use_case = config_use_case(repo)
    repo.should_fail = True

    assert use_case.remove_directory(original[0]) is False
    assert use_case.get_directories() == original
    assert repo.load_paths() == original


def test_failed_auto_detect_does_not_report_added_paths_or_change_memory(tmp_path: Path) -> None:
    original = [tmp_path / "existing"]
    repo = MemoryConfigAdapter(original)
    use_case = config_use_case(repo, [tmp_path / "discovered"])
    repo.should_fail = True

    assert use_case.auto_detect() == 0
    assert use_case.get_directories() == original
    assert repo.load_paths() == original


def test_replace_directories_persists_complete_list_once(tmp_path: Path) -> None:
    repo = CountingConfigAdapter([tmp_path / "old"])
    use_case = config_use_case(repo)
    replacement = [tmp_path / "first", tmp_path / "second"]

    assert use_case.replace_directories(replacement) is True

    assert repo.save_attempts == [replacement]
    assert use_case.get_directories() == replacement
    assert repo.load_paths() == replacement
    replacement.append(tmp_path / "caller-change")
    assert use_case.get_directories() == repo.load_paths()
    assert len(use_case.get_directories()) == 2


def test_failed_replacement_keeps_original_state_and_can_be_retried(tmp_path: Path) -> None:
    original = [tmp_path / "old"]
    repo = CountingConfigAdapter(original)
    use_case = config_use_case(repo)
    replacement = [tmp_path / "new"]
    repo.should_fail = True

    assert use_case.replace_directories(replacement) is False
    assert use_case.get_directories() == original
    assert repo.load_paths() == original
    assert repo.save_attempts == [replacement]

    repo.should_fail = False
    assert use_case.replace_directories(replacement) is True
    assert use_case.get_directories() == replacement
    assert repo.load_paths() == replacement
    assert repo.save_attempts == [replacement, replacement]


def test_replacing_with_empty_list_removes_all_paths_in_one_save(tmp_path: Path) -> None:
    repo = CountingConfigAdapter([tmp_path / "old"])
    use_case = config_use_case(repo)

    assert use_case.replace_directories([]) is True

    assert repo.save_attempts == [[]]
    assert use_case.get_directories() == []
    assert repo.load_paths() == []


def test_discovery_uses_draft_paths_without_mutating_repository(tmp_path: Path) -> None:
    original = [tmp_path / "old"]
    draft = [tmp_path / "draft"]
    repo = CountingConfigAdapter(original)
    use_case = config_use_case(repo, [draft[0] / "child", tmp_path / "discovered"])

    discovered = use_case.discover_directories(draft)

    assert discovered == [draft[0], tmp_path / "discovered"]
    assert draft == [tmp_path / "draft"]
    assert use_case.get_directories() == original
    assert repo.load_paths() == original
    assert repo.save_attempts == []
