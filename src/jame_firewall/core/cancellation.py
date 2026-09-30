"""Cooperative shutdown shared by the production I/O adapters."""

from threading import Event

from jame_firewall.core.exceptions import OperationCancelledError


class CancellationToken:
    """Stop between I/O operations; an already committed mutation is never rolled back."""

    def __init__(self) -> None:
        self._cancelled = Event()

    def cancel(self) -> None:
        """Request cancellation permanently and safely from any thread."""
        self._cancelled.set()

    def check(self) -> None:
        """Reject further work once shutdown has been requested."""
        if self._cancelled.is_set():
            raise OperationCancelledError("Operation cancelled during application shutdown")
