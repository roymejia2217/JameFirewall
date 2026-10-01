"""Portable process I/O contract; Windows supplies its own contained native launch."""

import contextlib
import os
import signal
import subprocess
import time
from typing import Protocol

CLEANUP_TIMEOUT_SECONDS = 5.0


class ProcessIO(Protocol):
    def read(self, stream: int, size: int) -> bytes | None:
        """None means no data yet; empty bytes means EOF."""
        ...

    def poll(self) -> int | None: ...

    def finish(self) -> None:
        """Reclaim descendants, retaining pipe readers for bounded final draining."""
        ...

    def close(self) -> None:
        """Reap the process and release every owned I/O resource."""
        ...


class PosixProcess:
    """A separate session prevents a timeout from leaving pipe-owning children behind."""

    def __init__(self, args: list[str], environment: dict[str, str] | None) -> None:
        self._process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=environment,
            start_new_session=True,
        )
        if self._process.stdout is None or self._process.stderr is None:
            raise OSError("Process pipes were not created")
        self._streams = (self._process.stdout, self._process.stderr)
        self._finished = False
        self._cleanup_deadline: float | None = None
        try:
            for stream in self._streams:
                os.set_blocking(stream.fileno(), False)
        except BaseException:
            self.close()
            raise

    def read(self, stream: int, size: int) -> bytes | None:
        try:
            return os.read(self._streams[stream].fileno(), size)
        except BlockingIOError:
            return None

    def poll(self) -> int | None:
        return self._process.poll()

    def finish(self) -> None:
        if self._finished:
            return
        if self._cleanup_deadline is None:
            self._cleanup_deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self._process.pid, signal.SIGKILL)
        self._process.wait(timeout=max(0.0, self._cleanup_deadline - time.monotonic()))
        self._finished = True

    def close(self) -> None:
        try:
            self.finish()
        finally:
            for stream in self._streams:
                stream.close()
