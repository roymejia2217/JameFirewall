"""Pruebas unitarias para ScanAndPruneDirectoriesUseCase."""

from pathlib import Path
from unittest.mock import MagicMock

from jame_firewall.core.entities import ScanIssue, ScanResult
from jame_firewall.core.use_cases.scan_directories import ScanAndPruneDirectoriesUseCase


def test_scan_use_case_delegates_to_scanner() -> None:
    scanner_mock = MagicMock()
    scanner_mock.prune_redundant_paths.return_value = [Path("/app")]
    scanner_mock.find_executables.return_value = ScanResult(executables=(Path("/app/app.exe"),))

    use_case = ScanAndPruneDirectoriesUseCase(scanner=scanner_mock)

    pruned = use_case.execute([Path("/app"), Path("/app/child")])
    assert pruned == [Path("/app")]
    scanner_mock.prune_redundant_paths.assert_called_once()

    exes = use_case.find_all_executables([Path("/app")])
    assert exes.executables == (Path("/app/app.exe"),)
    scanner_mock.find_executables.assert_called_once_with([Path("/app")])


def test_scan_use_case_preserves_incomplete_result_and_diagnostics() -> None:
    scanner = MagicMock()
    result = ScanResult(
        executables=(Path("/app/app.exe"),),
        issues=(ScanIssue(Path("/app/private"), "Acceso denegado"),),
        visited_directories=2,
        visited_entries=3,
    )
    scanner.find_executables.return_value = result
    observed = ScanAndPruneDirectoriesUseCase(scanner).find_all_executables([Path("/app")])
    assert observed is result
    assert not observed.complete
    assert "Escaneo incompleto" in observed.detail
