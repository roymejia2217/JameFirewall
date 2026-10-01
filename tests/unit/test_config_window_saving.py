"""The configuration modal commits a complete draft only when Save succeeds."""

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

from jame_firewall.presentation.windows.config_window import ConfigWindow


@dataclass
class DraftUseCase:
    saved: list[Path]
    save_success: bool = True
    replacement_attempts: list[list[Path]] = field(default_factory=list)
    discovery_inputs: list[list[Path]] = field(default_factory=list)
    discovered: list[Path] = field(default_factory=list)

    def get_directories(self) -> list[Path]:
        return list(self.saved)

    def replace_directories(self, paths: list[Path]) -> bool:
        self.replacement_attempts.append(list(paths))
        if self.save_success:
            self.saved = list(paths)
        return self.save_success

    def add_directory(self, path: Path) -> bool:
        raise AssertionError("Modal must not persist partial additions")

    def remove_directory(self, path: Path) -> bool:
        raise AssertionError("Modal must not persist partial removals")

    def auto_detect(self) -> int:
        raise AssertionError("Auto-detection must not save before the user selects Save")

    def discover_directories(self, paths: list[Path]) -> list[Path]:
        self.discovery_inputs.append(list(paths))
        return [*paths, *self.discovered]


@dataclass
class DraftWindow:
    _manage_config_uc: DraftUseCase
    current_dirs: list[str]
    _on_saved_callback: Callable[[str], None] | None = None
    listbox: MagicMock = field(default_factory=MagicMock)
    destroyed: bool = False

    def destroy(self) -> None:
        self.destroyed = True


def test_failed_save_preserves_modal_and_draft_without_success_callback(tmp_path: Path) -> None:
    original = [tmp_path / "old"]
    edited = [str(tmp_path / "new"), str(tmp_path / "another")]
    use_case = DraftUseCase(original, save_success=False)
    callback = MagicMock()
    window = DraftWindow(use_case, list(edited), callback)

    with patch("jame_firewall.presentation.windows.config_window.messagebox.showerror") as error:
        ConfigWindow.save_and_close(cast(ConfigWindow, window))

    assert use_case.replacement_attempts == [[Path(path) for path in edited]]
    assert use_case.saved == original
    assert window.current_dirs == edited
    assert not window.destroyed
    callback.assert_not_called()
    error.assert_called_once()


def test_successful_save_commits_once_then_notifies_and_closes(tmp_path: Path) -> None:
    edited = [str(tmp_path / "new"), str(tmp_path / "another")]
    use_case = DraftUseCase([tmp_path / "old"])
    observed: list[tuple[str, list[Path], bool]] = []
    window = DraftWindow(use_case, edited)

    def callback(message: str) -> None:
        observed.append((message, list(use_case.saved), window.destroyed))

    window._on_saved_callback = callback
    with patch("jame_firewall.presentation.windows.config_window.messagebox.showerror") as error:
        ConfigWindow.save_and_close(cast(ConfigWindow, window))

    expected = [Path(path) for path in edited]
    assert use_case.replacement_attempts == [expected]
    assert use_case.saved == expected
    assert window.destroyed
    assert len(observed) == 1
    assert observed[0][0]
    assert observed[0][1:] == (expected, False)
    error.assert_not_called()


def test_auto_detect_edits_draft_and_cancel_discards_it(tmp_path: Path) -> None:
    original = [tmp_path / "old"]
    draft = [tmp_path / "manual"]
    discovered = tmp_path / "discovered"
    use_case = DraftUseCase(original, discovered=[discovered])
    callback = MagicMock()
    window = DraftWindow(use_case, [str(path) for path in draft], callback)

    with patch("jame_firewall.presentation.windows.config_window.messagebox.showinfo"):
        ConfigWindow.auto_detect(cast(ConfigWindow, window))
    window.destroy()

    assert use_case.discovery_inputs == [draft]
    assert window.current_dirs == [str(draft[0]), str(discovered)]
    assert use_case.saved == original
    assert use_case.replacement_attempts == []
    callback.assert_not_called()
    assert window.destroyed
