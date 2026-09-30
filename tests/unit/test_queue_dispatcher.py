"""Deterministic lifecycle regressions for QueueDispatcher."""

import threading
import time
from collections.abc import Callable
from functools import partial

from jame_firewall.presentation.queue_dispatcher import QueueDispatcher


class DummyRoot:
    """A Tk scheduler that records callbacks without an event loop."""

    def __init__(self) -> None:
        self.logs: list[tuple[str, str]] = []
        self.scheduled: list[tuple[int, Callable[[], None]]] = []
        self.cancelled: list[str] = []
        self.tk_threads: list[int] = []

    def after(self, delay: int, callback: Callable[[], None]) -> str:
        self.tk_threads.append(threading.get_ident())
        self.scheduled.append((delay, callback))
        return f"after-{len(self.scheduled)}"

    def after_cancel(self, token: str) -> None:
        self.tk_threads.append(threading.get_ident())
        self.cancelled.append(token)

    def append_log(self, message: str, level: str) -> None:
        self.tk_threads.append(threading.get_ident())
        self.logs.append((message, level))


def wait_until(predicate: Callable[[], bool]) -> None:
    """Wait for a worker state transition with a bounded failure deadline."""
    deadline = time.monotonic() + 2
    tick = threading.Event()
    while not predicate():
        assert time.monotonic() < deadline, "Worker did not settle"
        tick.wait(0.001)


def test_queue_dispatcher_posts_log_and_drains_on_main_thread() -> None:
    root = DummyRoot()
    dispatcher = QueueDispatcher(root_tk=root, log_sink=root.append_log)
    try:
        dispatcher.post_log("Test message", "info")
        dispatcher.drain_queues()
        assert root.logs == [("Test message", "info")]
        assert root.scheduled
        assert set(root.tk_threads) == {threading.get_ident()}
    finally:
        dispatcher.shutdown()


def test_single_admission_until_main_thread_settles_completed_task() -> None:
    root = DummyRoot()
    dispatcher = QueueDispatcher(root_tk=root)
    started = threading.Event()
    release = threading.Event()
    completed = threading.Event()
    ui_threads: list[int] = []
    completion_threads: list[int] = []

    def work() -> None:
        started.set()
        assert release.wait(2)
        dispatcher.post_ui_update(lambda: ui_threads.append(threading.get_ident()))
        completed.set()

    try:
        assert (
            dispatcher.submit_background_task(
                work, on_complete=lambda: completion_threads.append(threading.get_ident())
            )
            is True
        )
        assert started.wait(2)
        assert dispatcher.is_busy is True
        assert dispatcher.is_idle is False
        assert dispatcher.submit_background_task(lambda: None) is False
        release.set()
        assert completed.wait(2)
        # Completion must be settled on the UI thread before admitting new work.
        assert dispatcher.submit_background_task(lambda: None) is False
        assert ui_threads == []

        def settled() -> bool:
            dispatcher.drain_queues()
            return not dispatcher.is_busy

        wait_until(settled)
        assert ui_threads == [threading.get_ident()]
        assert completion_threads == [threading.get_ident()]
        dispatcher.drain_queues()
        assert completion_threads == [threading.get_ident()]
        assert dispatcher.is_idle is True
        assert dispatcher.submit_background_task(lambda: None) is True
    finally:
        release.set()
        dispatcher.shutdown()


def test_shutdown_cancels_poll_and_suppresses_pending_and_late_updates() -> None:
    root = DummyRoot()
    dispatcher = QueueDispatcher(root_tk=root, log_sink=root.append_log)
    ui_calls: list[str] = []
    dispatcher.post_ui_update(lambda: ui_calls.append("pending"))
    dispatcher.post_log("pending")
    stale_poll = root.scheduled[-1][1]

    dispatcher.shutdown()
    dispatcher.shutdown()  # Closing twice is harmless.
    assert root.cancelled == ["after-1"]
    assert dispatcher.submit_background_task(lambda: None) is False
    dispatcher.post_ui_update(lambda: ui_calls.append("late"))
    dispatcher.post_log("late")
    dispatcher.drain_queues()
    stale_poll()

    assert ui_calls == []
    assert root.logs == []
    assert len(root.scheduled) == 1
    assert dispatcher.is_idle is True
    assert set(root.tk_threads) == {threading.get_ident()}


def test_completion_waits_for_admitted_callbacks_to_drain() -> None:
    root = DummyRoot()
    dispatcher = QueueDispatcher(root_tk=root, log_sink=root.append_log)
    finished = threading.Event()
    completion_counts: list[int] = []

    def work() -> None:
        for index in range(150):
            dispatcher.post_log(str(index))
        finished.set()

    try:
        assert (
            dispatcher.submit_background_task(
                work, on_complete=lambda: completion_counts.append(len(root.logs))
            )
            is True
        )
        assert finished.wait(2)
        dispatcher.drain_queues()
        assert dispatcher.is_busy is True
        assert completion_counts == []
        assert dispatcher.submit_background_task(lambda: None) is False

        def settled() -> bool:
            dispatcher.drain_queues()
            return not dispatcher.is_busy

        wait_until(settled)
        assert completion_counts == [150]
    finally:
        dispatcher.shutdown()


def test_competing_threads_admit_only_one_worker() -> None:
    root = DummyRoot()
    dispatcher = QueueDispatcher(root_tk=root)
    barrier = threading.Barrier(3)
    release = threading.Event()
    admissions: list[bool] = []

    def work() -> None:
        assert release.wait(2)

    def submit() -> None:
        barrier.wait(timeout=2)
        admissions.append(dispatcher.submit_background_task(work))

    threads = [threading.Thread(target=submit) for _ in range(2)]
    try:
        for thread in threads:
            thread.start()
        barrier.wait(timeout=2)
        for thread in threads:
            thread.join(timeout=2)
            assert not thread.is_alive()
        assert sorted(admissions) == [False, True]
        assert set(root.tk_threads) == {threading.get_ident()}
    finally:
        release.set()
        dispatcher.shutdown()


def test_shutdown_returns_while_worker_runs_and_exposes_safe_close_state() -> None:
    root = DummyRoot()
    dispatcher = QueueDispatcher(root_tk=root, log_sink=root.append_log)
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def work() -> None:
        started.set()
        assert release.wait(2)
        dispatcher.post_log("late worker log")
        finished.set()

    try:
        assert dispatcher.submit_background_task(work) is True
        assert started.wait(2)
        dispatcher.shutdown()
        assert dispatcher.is_idle is False
        assert not finished.is_set()
        assert dispatcher.submit_background_task(lambda: None) is False
        release.set()
        assert finished.wait(2)
        wait_until(lambda: dispatcher.is_idle)
        dispatcher.drain_queues()
        assert root.logs == []
    finally:
        release.set()
        dispatcher.shutdown()


def test_background_exception_is_reported_on_main_thread() -> None:
    root = DummyRoot()
    dispatcher = QueueDispatcher(root_tk=root, log_sink=root.append_log)
    failed = threading.Event()

    def work() -> None:
        failed.set()
        raise RuntimeError("worker failure")

    try:
        assert dispatcher.submit_background_task(work) is True
        assert failed.wait(2)
        assert root.logs == []

        def reported() -> bool:
            dispatcher.drain_queues()
            return bool(root.logs)

        wait_until(reported)
        assert any("worker failure" in message for message, _ in root.logs)
        assert any(level == "error" for _, level in root.logs)
        assert set(root.tk_threads) == {threading.get_ident()}
    finally:
        dispatcher.shutdown()


def test_flood_is_bounded_and_drain_has_a_combined_callback_budget() -> None:
    root = DummyRoot()
    dispatcher = QueueDispatcher(root_tk=root, log_sink=root.append_log)
    ui_calls: list[int] = []
    try:
        for index in range(1000):
            dispatcher.post_log(str(index))
            dispatcher.post_ui_update(partial(ui_calls.append, index))

        assert 0 < dispatcher._ui_queue.qsize() < 1000
        assert 0 < dispatcher._log_queue.qsize() < 1000
        dispatcher.drain_queues()
        assert 0 < len(ui_calls) + len(root.logs) <= 100
        assert dispatcher._ui_queue.qsize() + dispatcher._log_queue.qsize() > 0
    finally:
        dispatcher.shutdown()
