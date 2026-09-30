"""Single-operation dispatcher; only the Tk thread settles work and renders updates."""

import queue
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Lock
from typing import Any, Protocol


class TkSchedulerPort(Protocol):
    """Contrato mínimo requerido del event loop de Tk."""

    def after(self, delay_ms: int, callback: Callable[[], None]) -> Any:
        """Programa un callback en el hilo del event loop."""
        ...

    def after_cancel(self, token: Any) -> None:
        """Cancela un callback desde el hilo del event loop."""
        ...


class QueueDispatcher:
    """Reject overlapping operations and bound the work done on each Tk poll."""

    def __init__(
        self,
        root_tk: TkSchedulerPort,
        log_sink: Callable[[str, str], None] | None = None,
        max_workers: int = 1,
    ) -> None:
        self._root = root_tk
        self._log_sink = log_sink
        self._ui_queue: queue.Queue[Callable[[], None]] = queue.Queue(maxsize=128)
        self._log_queue: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=256)
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="JameWorker"
        )
        self._lock = Lock()
        self._future: Future[Any] | None = None
        self._on_complete: Callable[[], None] | None = None
        self._is_running = True
        self._poll_token: Any = None
        self._dropped = 0
        self._ui_turn = True
        self._schedule_poll()

    @property
    def is_busy(self) -> bool:
        """Admission remains closed until the main thread consumes the completed work."""
        with self._lock:
            return self._future is not None

    @property
    def is_idle(self) -> bool:
        """After shutdown, true only when the running worker has actually finished."""
        with self._lock:
            return self._future is None or (not self._is_running and self._future.done())

    def submit_background_task(
        self,
        task_callable: Callable[..., Any],
        *args: Any,
        on_complete: Callable[[], None] | None = None,
        **kwargs: Any,
    ) -> bool:
        """Admit one task atomically, without an unbounded pending executor queue."""
        with self._lock:
            if not self._is_running or self._future is not None:
                return False
            self._future = self._executor.submit(task_callable, *args, **kwargs)
            self._on_complete = on_complete
            return True

    def post_ui_update(self, update_callback: Callable[[], None]) -> None:
        """Keep recent visual updates without ever calling Tk on a worker."""
        with self._lock:
            if self._is_running:
                if self._ui_queue.full():
                    self._ui_queue.get_nowait()
                    self._dropped += 1
                self._ui_queue.put_nowait(update_callback)

    def post_log(self, message: str, level: str = "info") -> None:
        """Retain a bounded tail of messages; report overflow on the main thread."""
        with self._lock:
            if self._is_running:
                if self._log_queue.full():
                    self._log_queue.get_nowait()
                    self._dropped += 1
                self._log_queue.put_nowait((message[:4096], level))

    def _schedule_poll(self) -> None:
        if not self._is_running:
            return
        self.drain_queues()
        if self._is_running:
            self._poll_token = self._root.after(100, self._schedule_poll)

    def _report_failure(self, message: str) -> None:
        if self._log_sink is not None:
            self._log_sink(message, "error")

    def drain_queues(self) -> None:
        """Process at most 100 queued updates per turn, then settle completed work."""
        if not self._is_running:
            return
        with self._lock:
            dropped, self._dropped = self._dropped, 0
        if dropped and self._log_sink is not None:
            self._log_sink(
                f"Se omitieron {dropped} actualizaciones por exceso de actividad.", "warn"
            )
        for _ in range(100 - bool(dropped)):
            # Alternate queues so status updates and logs both make progress.
            consumed = False
            queues: tuple[queue.Queue[Any], ...] = (self._ui_queue, self._log_queue)
            if not self._ui_turn:
                queues = (self._log_queue, self._ui_queue)
            self._ui_turn = not self._ui_turn
            for events in queues:
                try:
                    entry = events.get_nowait()
                except queue.Empty:
                    continue
                try:
                    if callable(entry):
                        entry()
                    elif self._log_sink is not None:
                        self._log_sink(*entry)
                except Exception as ex:
                    self._report_failure(f"Error actualizando la interfaz: {ex}")
                consumed = True
                break
            if not consumed or not self._is_running:
                break
        with self._lock:
            future = self._future
            settle = (
                self._is_running
                and future is not None
                and future.done()
                and self._ui_queue.empty()
                and self._log_queue.empty()
            )
            completion = self._on_complete if settle else None
            if settle:
                self._future = None
                self._on_complete = None
        if settle and future is not None:
            try:
                future.result()
            except Exception as ex:
                self._report_failure(f"Error en la operación: {ex}")
            if completion is not None:
                completion()

    def shutdown(self, wait: bool = False) -> None:
        """Reject work, suppress late updates and release threads once their task exits."""
        with self._lock:
            self._is_running = False
            token, self._poll_token = self._poll_token, None
            self._on_complete = None
            for events in (self._ui_queue, self._log_queue):
                while not events.empty():
                    events.get_nowait()
        if token is not None:
            self._root.after_cancel(token)
        self._executor.shutdown(wait=wait, cancel_futures=True)
