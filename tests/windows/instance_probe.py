"""Controlled child processes for native mutex contention and abandonment proofs."""

import sys
import time
from pathlib import Path

from jame_firewall.infrastructure.os.instance_lock import WindowsInstanceLock


def main() -> None:
    name, ready, stop, start = sys.argv[1:]
    deadline = time.monotonic() + 10
    while not Path(start).exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("Native instance probe was never released")
        time.sleep(0.01)
    lock = WindowsInstanceLock(name)
    acquired = lock.acquire()
    try:
        marker = Path(ready)
        pending = marker.with_name(marker.name + ".tmp")
        pending.write_text("owned" if acquired else "busy", encoding="utf-8")
        pending.replace(marker)
        print("owned" if acquired else "busy", flush=True)
        if acquired:
            while not Path(stop).exists():
                time.sleep(0.01)
    finally:
        lock.release()


if __name__ == "__main__":
    main()
