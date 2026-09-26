"""Pruebas unitarias para QueueDispatcher."""

import time

from jame_firewall.presentation.queue_dispatcher import QueueDispatcher


class DummyRoot:
    """Simulador de Tkinter root para pruebas sin servidor X11/Display."""

    def __init__(self) -> None:
        self.logs: list[tuple[str, str]] = []
        self.scheduled: list[tuple[int, object]] = []

    def after(self, delay: int, callback: object) -> None:
        self.scheduled.append((delay, callback))

    def append_log(self, message: str, level: str) -> None:
        self.logs.append((message, level))


def test_queue_dispatcher_posts_log_and_drains() -> None:
    root = DummyRoot()
    dispatcher = QueueDispatcher(root_tk=root, log_sink=root.append_log)

    dispatcher.post_log("Test message", "info")
    dispatcher.drain_queues()

    assert len(root.logs) == 1
    assert root.logs[0] == ("Test message", "info")
    assert root.scheduled

    dispatcher.shutdown()


def test_queue_dispatcher_background_task() -> None:
    root = DummyRoot()
    dispatcher = QueueDispatcher(root_tk=root)
    state = {"executed": False}

    def background_work() -> None:
        time.sleep(0.01)
        state["executed"] = True

    dispatcher.submit_background_task(background_work)
    time.sleep(0.05)

    assert state["executed"] is True
    dispatcher.shutdown()
