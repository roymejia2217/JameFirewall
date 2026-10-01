"""Startup must elevate before acquiring exclusive ownership of the application."""

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from jame_firewall import __main__ as entry


@dataclass
class StartupHarness:
    admin: bool = True
    elevation_allowed: bool = True
    available: bool = True
    fail_at: str | None = None
    held: bool = False
    events: list[str] = field(default_factory=list)
    notices: list[tuple[str, bool, bool]] = field(default_factory=list)

    def step(self, name: str) -> None:
        self.events.append(name)
        if self.fail_at == name:
            raise OSError(f"{name} failed")

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        harness = self

        class FakeUAC:
            def is_admin(self) -> bool:
                harness.step("admin")
                return harness.admin

            def request_elevation(self) -> bool:
                harness.step("elevate")
                return harness.elevation_allowed

        class FakeLock:
            def __init__(self) -> None:
                harness.step("lock")

            def acquire(self) -> bool:
                harness.step("acquire")
                harness.held = harness.available
                return harness.available

            def release(self) -> None:
                assert harness.held, "Cannot release ownership that was never acquired"
                harness.step("release")
                harness.held = False

        class FakeContainer:
            @classmethod
            def create_production(cls) -> object:
                assert harness.held, "Configuration must not open before exclusive ownership"
                harness.step("container")
                return object()

        class FakeApp:
            def __init__(self, container: object) -> None:
                assert harness.held, "UI must not open before exclusive ownership"
                harness.step("app")

            def run(self) -> None:
                assert harness.held
                harness.step("run")

            def dispose(self) -> None:
                assert harness.held, "Keep ownership until all operation workers stop"
                harness.step("workers_closed")

        def notify(message: str, *, duplicate: bool = False, error: bool = False) -> None:
            harness.notices.append((message, duplicate, error))

        monkeypatch.setattr(entry, "WindowsUACAdapter", FakeUAC)
        monkeypatch.setattr(entry, "WindowsInstanceLock", FakeLock, raising=False)
        monkeypatch.setattr(entry, "AppContainer", FakeContainer)
        monkeypatch.setattr(entry, "JameFirewallApp", FakeApp)
        monkeypatch.setattr(entry, "_notify_startup", notify, raising=False)


@pytest.fixture
def startup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> StartupHarness:
    monkeypatch.chdir(tmp_path)
    harness = StartupHarness()
    harness.install(monkeypatch)
    return harness


def test_elevation_parent_returns_before_creating_lock_or_application(
    startup: StartupHarness,
) -> None:
    startup.admin = False

    entry.main()

    assert startup.events == ["admin", "elevate"]
    assert startup.notices == []


def test_refused_elevation_shows_error_and_never_opens_configuration(
    startup: StartupHarness,
) -> None:
    startup.admin = False
    startup.elevation_allowed = False

    entry.main()

    assert startup.events == ["admin", "elevate"]
    assert len(startup.notices) == 1
    message, duplicate, error = startup.notices[0]
    assert message
    assert error and not duplicate


def test_second_instance_reports_duplicate_without_opening_configuration(
    startup: StartupHarness,
) -> None:
    startup.available = False

    entry.main()

    assert startup.events == ["admin", "lock", "acquire"]
    assert not startup.held
    assert len(startup.notices) == 1
    message, duplicate, error = startup.notices[0]
    assert message
    assert duplicate and not error


def test_instance_owns_application_until_workers_have_closed(startup: StartupHarness) -> None:
    entry.main()

    assert startup.events == [
        "admin",
        "lock",
        "acquire",
        "container",
        "app",
        "run",
        "workers_closed",
        "release",
    ]
    assert not startup.held
    assert startup.notices == []


@pytest.mark.parametrize("stage", ["lock", "acquire"])
def test_ownership_errors_fail_closed_without_false_duplicate_notice(
    startup: StartupHarness, stage: str
) -> None:
    startup.fail_at = stage

    entry.main()

    assert "container" not in startup.events
    assert "app" not in startup.events
    assert "release" not in startup.events
    assert not startup.held
    assert len(startup.notices) == 1
    message, duplicate, error = startup.notices[0]
    assert message
    assert error and not duplicate


@pytest.mark.parametrize("stage", ["container", "app", "run"])
def test_application_failures_release_ownership_and_report_error(
    startup: StartupHarness, stage: str
) -> None:
    startup.fail_at = stage

    entry.main()

    assert startup.events[-1] == "release"
    if stage == "run":
        assert startup.events[-2] == "workers_closed"
    else:
        assert "workers_closed" not in startup.events
    assert not startup.held
    assert len(startup.notices) == 1
    message, duplicate, error = startup.notices[0]
    assert message
    assert error and not duplicate


def test_elevation_error_never_constructs_lock(startup: StartupHarness) -> None:
    startup.admin = False
    startup.fail_at = "elevate"

    entry.main()

    assert startup.events == ["admin", "elevate"]
    assert len(startup.notices) == 1
    message, duplicate, error = startup.notices[0]
    assert message
    assert error and not duplicate


def test_failed_worker_cleanup_keeps_ownership_until_process_exit(
    startup: StartupHarness,
) -> None:
    startup.fail_at = "workers_closed"

    entry.main()

    assert startup.held
    assert "release" not in startup.events
    assert len(startup.notices) == 1
    message, duplicate, error = startup.notices[0]
    assert message
    assert error and not duplicate
