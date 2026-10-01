"""One cooperative deadline shared across nested steps of an admitted operation."""

import math
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from jame_firewall.core.exceptions import OperationDeadlineExceeded

OPERATION_TIMEOUT_SECONDS = 120.0


@dataclass(frozen=True)
class _Budget:
    deadline: float
    clock: Callable[[], float]


_current: ContextVar[_Budget | None] = ContextVar("operation_budget", default=None)


@contextmanager
def operation_budget(
    seconds: float = OPERATION_TIMEOUT_SECONDS, *, clock: Callable[[], float] = time.monotonic
) -> Iterator[None]:
    """Nested steps inherit the current deadline and never extend it."""
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("Operation deadline must be positive and finite")
    if _current.get() is not None:
        yield
        return
    token = _current.set(_Budget(clock() + seconds, clock))
    try:
        yield
    finally:
        _current.reset(token)


def remaining_operation_seconds() -> float | None:
    budget = _current.get()
    if budget is None:
        return None
    remaining = budget.deadline - budget.clock()
    if remaining <= 0:
        raise OperationDeadlineExceeded(
            "Se agotó el tiempo de la operación. Los cambios ya aplicados no se revierten; "
            "actualice el estado antes de volver a intentar."
        )
    return remaining


def check_operation_budget() -> None:
    remaining_operation_seconds()
