"""Pruebas unitarias para el Composition Root (AppContainer)."""

from pathlib import Path

from jame_firewall.infrastructure.container import AppContainer


def test_app_container_create_production(tmp_path: Path) -> None:
    config_file = tmp_path / "jamefirewall_config.json"
    container = AppContainer.create_production(config_path=config_file)

    assert container.firewall is not None
    assert container.process_runner is not None
    assert container.directory_scanner is not None
    assert container.config_repository is not None
    assert container.registry_discovery is not None
    assert container.uac is not None

    assert container.block_use_case is not None
    assert container.unblock_use_case is not None
    assert container.scan_use_case is not None
    assert container.config_use_case is not None
    assert container.audit_use_case is not None
