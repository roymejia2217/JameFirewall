"""The configuration modal commits a complete draft only when Save succeeds."""

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

import pytest

from jame_firewall.presentation.windows.config_window import ConfigWindow


@dataclass
class DraftUseCase:
    saved: list[Path]
    save_success: bool = True
    replacement_attempts: list[list[Path]] = field(default_factory=list)
    discovery_inputs: list[list[Path]] = field(default_factory=list)
    discovered: list[Path] = field(default_factory=list)
    discovery_error: Exception | None = None

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
        if self.discovery_error is not None:
            raise self.discovery_error
        return [*paths, *self.discovered]


@dataclass
class DeferredDispatcher:
    tasks: list[Callable[[], None]] = field(default_factory=list)
    updates: list[Callable[[], None]] = field(default_factory=list)
    accept: bool = True
    worker_running: bool = False

    def submit_background_task(
        self, task: Callable[[], None], *, on_complete: Callable[[], None] | None = None
    ) -> bool:
        if not self.accept:
            return False

        def worker() -> None:
            try:
                task()
            finally:
                if on_complete is not None:
                    self.post_ui_update(on_complete)

        self.tasks.append(worker)
        return True

    def post_ui_update(self, callback: Callable[[], None]) -> None:
        self.updates.append(callback)

    def run_worker(self) -> None:
        self.worker_running = True
        try:
            self.tasks.pop(0)()
        finally:
            self.worker_running = False

    def deliver_updates(self) -> None:
        while self.updates:
            self.updates.pop(0)()


@dataclass
class DraftWindow:
    _manage_config_uc: DraftUseCase
    current_dirs: list[str]
    _on_saved_callback: Callable[[str], None] | None = None
    listbox: MagicMock = field(default_factory=MagicMock)
    destroyed: bool = False
    _dispatcher: DeferredDispatcher = field(default_factory=DeferredDispatcher)
    _discovering: bool = False
    _closed: bool = False
    _on_busy_callback: Callable[[bool], None] | None = None
    btn_add: MagicMock = field(default_factory=MagicMock)
    btn_remove: MagicMock = field(default_factory=MagicMock)
    btn_auto: MagicMock = field(default_factory=MagicMock)
    btn_save: MagicMock = field(default_factory=MagicMock)

    def _set_discovery_state(self, discovering: bool) -> None:
        ConfigWindow._set_discovery_state(cast(ConfigWindow, self), discovering)

    def destroy(self) -> None:
        self._closed = True
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
        window._dispatcher.run_worker()
        window._dispatcher.deliver_updates()
    window.destroy()

    assert use_case.discovery_inputs == [draft]
    assert window.current_dirs == [str(draft[0]), str(discovered)]
    assert use_case.saved == original
    assert use_case.replacement_attempts == []
    callback.assert_not_called()
    assert window.destroyed


def test_discovery_runs_off_ui_and_updates_only_through_dispatcher(tmp_path: Path) -> None:
    original = [str(tmp_path / "manual")]
    use_case = DraftUseCase([], discovered=[tmp_path / "found"])
    window = DraftWindow(use_case, list(original))

    def ui_only(*args: object, **kwargs: object) -> None:
        assert not window._dispatcher.worker_running, "Tk cannot be accessed by a worker"

    for widget in (
        window.listbox,
        window.btn_add,
        window.btn_remove,
        window.btn_auto,
        window.btn_save,
    ):
        widget.configure.side_effect = ui_only
        widget.config.side_effect = ui_only
        widget.delete.side_effect = ui_only
        widget.insert.side_effect = ui_only

    with patch("jame_firewall.presentation.windows.config_window.messagebox.showinfo") as notice:
        notice.side_effect = ui_only
        ConfigWindow.auto_detect(cast(ConfigWindow, window))
        assert use_case.discovery_inputs == []
        assert len(window._dispatcher.tasks) == 1
        assert window._discovering
        for button in (window.btn_add, window.btn_remove, window.btn_auto, window.btn_save):
            calls = [*button.configure.call_args_list, *button.config.call_args_list]
            assert any(call.kwargs.get("state") == "disabled" for call in calls)

        window._dispatcher.run_worker()
        assert use_case.discovery_inputs == [[Path(original[0])]]
        assert window.current_dirs == original
        window.listbox.delete.assert_not_called()
        notice.assert_not_called()
        assert window._dispatcher.updates
        window._dispatcher.deliver_updates()

        assert window.current_dirs == [*original, str(tmp_path / "found")]
        assert not window._discovering
        notice.assert_called_once()
        assert use_case.replacement_attempts == []


def test_discovery_error_preserves_draft_and_reports_on_ui(tmp_path: Path) -> None:
    draft = [str(tmp_path / "manual")]
    use_case = DraftUseCase([], discovery_error=OSError("registry unavailable"))
    window = DraftWindow(use_case, list(draft))

    with patch("jame_firewall.presentation.windows.config_window.messagebox.showerror") as error:
        ConfigWindow.auto_detect(cast(ConfigWindow, window))
        window._dispatcher.run_worker()
        error.assert_not_called()
        window._dispatcher.deliver_updates()
        error.assert_called_once()

    assert window.current_dirs == draft
    assert not window._discovering
    assert use_case.replacement_attempts == []


@pytest.mark.parametrize("fail", [False, True])
def test_cancel_suppresses_late_discovery_result_or_error(tmp_path: Path, fail: bool) -> None:
    draft = [str(tmp_path / "manual")]
    use_case = DraftUseCase(
        [],
        discovered=[tmp_path / "found"],
        discovery_error=OSError("registry unavailable") if fail else None,
    )
    window = DraftWindow(use_case, list(draft))
    with (
        patch("jame_firewall.presentation.windows.config_window.messagebox.showinfo") as info,
        patch("jame_firewall.presentation.windows.config_window.messagebox.showerror") as error,
    ):
        ConfigWindow.auto_detect(cast(ConfigWindow, window))
        window.destroy()
        window.listbox.reset_mock()
        window._dispatcher.run_worker()
        window._dispatcher.deliver_updates()
        info.assert_not_called()
        error.assert_not_called()
    assert window.current_dirs == draft
    window.listbox.delete.assert_not_called()
    window.listbox.insert.assert_not_called()


@pytest.mark.parametrize("operation", ["save_and_close", "add_dir", "remove_dir", "auto_detect"])
def test_discovering_modal_rejects_conflicting_commands(tmp_path: Path, operation: str) -> None:
    window = DraftWindow(DraftUseCase([]), [str(tmp_path / "manual")])
    window._discovering = True
    with patch(
        "jame_firewall.presentation.windows.config_window.filedialog.askdirectory"
    ) as picker:
        picker.return_value = str(tmp_path / "another")
        getattr(ConfigWindow, operation)(cast(ConfigWindow, window))
        picker.assert_not_called()
    assert window.current_dirs == [str(tmp_path / "manual")]
    assert window._manage_config_uc.replacement_attempts == []
    assert window._manage_config_uc.discovery_inputs == []
    assert window._dispatcher.tasks == []
    assert not window.destroyed


def test_busy_dispatcher_rejects_discovery_without_leaving_modal_disabled(tmp_path: Path) -> None:
    window = DraftWindow(DraftUseCase([]), [str(tmp_path / "manual")])
    window._dispatcher.accept = False
    with (
        patch("jame_firewall.presentation.windows.config_window.messagebox.showinfo"),
        patch("jame_firewall.presentation.windows.config_window.messagebox.showerror"),
    ):
        ConfigWindow.auto_detect(cast(ConfigWindow, window))
    assert window._dispatcher.tasks == []
    assert not window._discovering
    assert window._manage_config_uc.discovery_inputs == []
    assert not window.destroyed
