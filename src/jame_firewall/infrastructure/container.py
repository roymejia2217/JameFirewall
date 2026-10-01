"""Contenedor de Inyección de Dependencias y Composition Root para JameFirewall."""

from dataclasses import dataclass, field
from pathlib import Path

from jame_firewall.core.cancellation import CancellationToken
from jame_firewall.core.ports import (
    ConfigRepositoryPort,
    DirectoryScannerPort,
    FirewallPort,
    ProcessRunnerPort,
    RegistryDiscoveryPort,
    UACPort,
)
from jame_firewall.core.use_cases.audit_status import AuditFirewallStatusUseCase
from jame_firewall.core.use_cases.block_executables import BlockExecutablesUseCase
from jame_firewall.core.use_cases.manage_config import ManageConfigDirectoriesUseCase
from jame_firewall.core.use_cases.scan_directories import ScanAndPruneDirectoriesUseCase
from jame_firewall.core.use_cases.unblock_rules import UnblockRulesUseCase
from jame_firewall.infrastructure.firewall.netsh_adapter import WindowsNetshAdapter
from jame_firewall.infrastructure.os.filesystem import OSFileSystemAdapter
from jame_firewall.infrastructure.os.process_runner import SystemProcessRunner
from jame_firewall.infrastructure.os.registry_scanner import WindowsRegistryAdapter
from jame_firewall.infrastructure.os.uac_manager import WindowsUACAdapter
from jame_firewall.infrastructure.persistence.json_config import JsonConfigAdapter


@dataclass(frozen=True)
class AppContainer:
    """Contenedor tipado e inmutable para el ensamblaje de dependencias."""

    # Infraestructura
    process_runner: ProcessRunnerPort
    firewall: FirewallPort
    directory_scanner: DirectoryScannerPort
    config_repository: ConfigRepositoryPort
    registry_discovery: RegistryDiscoveryPort
    uac: UACPort

    # Casos de Uso
    block_use_case: BlockExecutablesUseCase
    unblock_use_case: UnblockRulesUseCase
    scan_use_case: ScanAndPruneDirectoriesUseCase
    config_use_case: ManageConfigDirectoriesUseCase
    audit_use_case: AuditFirewallStatusUseCase

    cancellation: CancellationToken = field(default_factory=CancellationToken)

    @classmethod
    def create_production(cls, config_path: Path | None = None) -> "AppContainer":
        """Construye y cablea el grafo de dependencias para producción."""
        cancellation = CancellationToken()
        runner = SystemProcessRunner(cancellation=cancellation)
        uac = WindowsUACAdapter()
        firewall = WindowsNetshAdapter(runner=runner)
        scanner = OSFileSystemAdapter(cancellation=cancellation)
        registry = WindowsRegistryAdapter(cancellation=cancellation)
        config_repo = JsonConfigAdapter(config_path=config_path)

        block_uc = BlockExecutablesUseCase(
            firewall=firewall,
            scanner=scanner,
            uac=uac,
            primary_suffix="jame-block",
        )

        unblock_uc = UnblockRulesUseCase(
            firewall=firewall,
            uac=uac,
            primary_suffix="jame-block",
            legacy_suffixes=["adobe-block"],
        )

        scan_uc = ScanAndPruneDirectoriesUseCase(scanner=scanner)

        config_uc = ManageConfigDirectoriesUseCase(
            config_repo=config_repo,
            registry=registry,
            scanner=scanner,
        )

        audit_uc = AuditFirewallStatusUseCase(
            scanner=scanner,
            firewall=firewall,
            uac=uac,
            primary_suffix="jame-block",
            legacy_suffixes=["adobe-block"],
        )

        return cls(
            cancellation=cancellation,
            process_runner=runner,
            firewall=firewall,
            directory_scanner=scanner,
            config_repository=config_repo,
            registry_discovery=registry,
            uac=uac,
            block_use_case=block_uc,
            unblock_use_case=unblock_uc,
            scan_use_case=scan_uc,
            config_use_case=config_uc,
            audit_use_case=audit_uc,
        )
