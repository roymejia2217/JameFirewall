"""Despachador concurrente de colas thread-safe para sincronización con Tkinter."""

import contextlib
import queue
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any


class QueueDispatcher:
    """Orquestador thread-safe entre hilos de trabajo y el bucle principal de Tkinter."""

    def __init__(self, root_tk: Any, max_workers: int = 2) -> None:
        self._root = root_tk
        self._ui_queue: queue.Queue[Callable[[], None]] = queue.Queue()
        self._log_queue: queue.Queue[dict[str, str]] = queue.Queue()
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="JameWorker"
        )
        self._is_running = True
        self._schedule_poll()

    def submit_background_task(
        self, task_callable: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> None:
        """Despacha tareas I/O pesadas al ThreadPoolExecutor."""
        self._executor.submit(task_callable, *args, **kwargs)

    def post_ui_update(self, update_callback: Callable[[], None]) -> None:
        """Encola una función de actualización visual para el Main Thread."""
        self._ui_queue.put(update_callback)

    def post_log(self, message: str, level: str = "info") -> None:
        """Encola un mensaje formateado para el widget de registro."""
        self._log_queue.put({"message": message, "level": level})

    def _schedule_poll(self) -> None:
        if self._is_running and hasattr(self._root, "after"):
            self.drain_queues()
            self._root.after(100, self._schedule_poll)

    def drain_queues(self) -> None:
        """Drena y procesa todos los mensajes pendientes en las colas."""
        while not self._ui_queue.empty():
            with contextlib.suppress(queue.Empty, Exception):
                callback = self._ui_queue.get_nowait()
                callback()

        while not self._log_queue.empty():
            with contextlib.suppress(queue.Empty, Exception):
                log_entry = self._log_queue.get_nowait()
                if hasattr(self._root, "append_log"):
                    self._root.append_log(log_entry["message"], log_entry["level"])

    def shutdown(self) -> None:
        """Detiene el despachador y apaga el pool de hilos."""
        self._is_running = False
        self._executor.shutdown(wait=False)
