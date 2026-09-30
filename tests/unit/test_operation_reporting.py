"""Portable controller checks for honest operation results and visible errors."""

from collections.abc import Callable
from unittest.mock import MagicMock, patch

import pytest

from jame_firewall.core.entities import BlockSummary, StatusSnapshot, SystemStatus, UnblockSummary
from jame_firewall.core.exceptions import FirewallExecutionError
from jame_firewall.presentation import constants as C
from jame_firewall.presentation.windows.main_window import JameFirewallApp


def controller() -> tuple[JameFirewallApp, MagicMock, MagicMock]:
    app = JameFirewallApp.__new__(JameFirewallApp)
    container = MagicMock()
    container.uac.is_admin.return_value = True
    container.config_use_case.get_directories.return_value = []
    container.audit_use_case.execute.return_value = StatusSnapshot(SystemStatus.PARTIAL, 1)
    dispatcher = MagicMock()
    dispatcher.is_busy = False
    dispatcher.submit_background_task.return_value = True
    app._closing = False
    app._container = container
    app.dispatcher = dispatcher
    return app, container, dispatcher


def run_scheduled_worker(dispatcher: MagicMock) -> None:
    dispatcher.submit_background_task.assert_called_once()
    worker: Callable[[], None] = dispatcher.submit_background_task.call_args.args[0]
    worker()
    for posted_update in dispatcher.post_ui_update.call_args_list:
        update: Callable[[], None] = posted_update.args[0]
        update()
    completion = dispatcher.submit_background_task.call_args.kwargs.get("on_complete")
    if completion is not None:
        completion()


@pytest.mark.parametrize("operation", ["block", "unblock"])
def test_failed_operation_never_reports_success(operation: str) -> None:
    app, container, dispatcher = controller()
    container.block_use_case.execute.return_value = BlockSummary(0, 0, 1, ["Partial rule"])
    container.unblock_use_case.execute.return_value = UnblockSummary(0, 1, ["Still present"])
    with patch.object(app, "_set_buttons_state"), patch.object(app, "_update_status_ui"):
        if operation == "block":
            app._on_block_clicked()
        else:
            app._on_unblock_clicked()
        run_scheduled_worker(dispatcher)
    success = C.MSG_SUCCESS_BLOCK if operation == "block" else C.MSG_SUCCESS_UNBLOCK
    messages = [call.args for call in dispatcher.post_log.call_args_list]
    assert (success, "ok") not in messages
    assert any(level == "err" for _, level in messages)


def test_retained_legacy_rules_produce_visible_warning() -> None:
    app, container, dispatcher = controller()
    container.unblock_use_case.execute.return_value = UnblockSummary(0, 0, retained_legacy_count=2)
    with patch.object(app, "_set_buttons_state"), patch.object(app, "_update_status_ui"):
        app._on_unblock_clicked()
        run_scheduled_worker(dispatcher)
    warnings = [
        call.args[0] for call in dispatcher.post_log.call_args_list if call.args[1] == "warn"
    ]
    assert warnings
    assert any("2" in message for message in warnings)


@pytest.mark.parametrize("operation", ["startup", "block", "unblock"])
def test_operation_exception_replaces_stale_status_with_visible_error(operation: str) -> None:
    app, container, dispatcher = controller()
    failure = FirewallExecutionError("Firewall query unavailable")
    if operation == "startup":
        container.audit_use_case.execute.side_effect = failure
    elif operation == "block":
        container.block_use_case.execute.side_effect = failure
    else:
        container.unblock_use_case.execute.side_effect = failure
    with (
        patch.object(app, "_set_buttons_state"),
        patch.object(app, "_update_status_ui") as update_status,
    ):
        if operation == "startup":
            app._start_async_init()
        elif operation == "block":
            app._on_block_clicked()
        else:
            app._on_unblock_clicked()
        run_scheduled_worker(dispatcher)
        snapshots = [call.args[0] for call in update_status.call_args_list]
    assert snapshots
    assert snapshots[-1].status == SystemStatus.ERROR
    assert any(call.args[1] == "err" for call in dispatcher.post_log.call_args_list)


@pytest.mark.parametrize("operation", ["startup", "refresh", "block", "unblock"])
def test_busy_controller_rejects_overlapping_operations(operation: str) -> None:
    app, container, dispatcher = controller()
    dispatcher.is_busy = True
    with patch.object(app, "_set_buttons_state"):
        {
            "startup": app._start_async_init,
            "refresh": app._on_refresh_clicked,
            "block": app._on_block_clicked,
            "unblock": app._on_unblock_clicked,
        }[operation]()
    dispatcher.submit_background_task.assert_not_called()
    container.audit_use_case.execute.assert_not_called()


def test_config_is_unavailable_during_operation() -> None:
    app, _, dispatcher = controller()
    dispatcher.is_busy = True
    app.root = MagicMock()
    with patch("jame_firewall.presentation.windows.main_window.ConfigWindow") as dialog:
        app._on_config_clicked()
    dialog.assert_not_called()


def test_close_waits_for_worker_without_blocking_tk() -> None:
    app, container, dispatcher = controller()
    app.root = MagicMock()
    app.status_label = MagicMock()
    dispatcher.is_idle = False
    with patch.object(app, "_set_buttons_state"):
        app._on_close()
        app._on_close()
    container.cancellation.cancel.assert_called_once()
    app.root.destroy.assert_not_called()
    app.root.after.assert_called_once()
    dispatcher.is_idle = True
    callback = app.root.after.call_args.args[1]
    callback()
    app.root.destroy.assert_called_once()


def test_no_admin_controls_remain_disabled_after_completion() -> None:
    app, container, _ = controller()
    container.uac.is_admin.return_value = False
    app.status_label = MagicMock()
    with patch.object(app, "_set_buttons_state") as controls:
        app._finish_operation()
    assert controls.call_args.args == ("disabled",)


def test_activity_log_retains_only_a_bounded_tail() -> None:
    app, _, _ = controller()
    app.log_text = MagicMock()
    app.log_text.text.index.return_value = "3001.0"
    app.append_log("x" * 10000)
    app.log_text.text.delete.assert_called_once()
    assert len(app.log_text.text.insert.call_args_list[-1].args[1]) < 5000
