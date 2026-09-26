"""Adaptador de Windows Defender Firewall basado en netsh y powershell."""

from pathlib import Path

from jame_firewall.core.entities import RuleDirection
from jame_firewall.core.ports import ProcessRunnerPort


class WindowsNetshAdapter:
    """Implementación de FirewallPort mediante netsh y PowerShell."""

    def __init__(self, runner: ProcessRunnerPort) -> None:
        self._runner = runner

    def add_rule(self, rule_name: str, program_path: Path, direction: RuleDirection) -> bool:
        """Crea una regla de bloqueo entrante o saliente para el programa especificado."""
        args = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            f"dir={direction.value}",
            f"program={program_path}",
            "action=block",
        ]
        code, _, _ = self._runner.run(args)
        return code == 0

    def delete_rule(self, rule_name: str) -> bool:
        """Elimina una regla por nombre del Firewall."""
        args = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]
        code, _, _ = self._runner.run(args)
        return code == 0

    def list_rules_with_suffix(self, suffix: str) -> list[str]:
        """Consulta reglas activas que contengan el sufijo indicado."""
        # 1. Intentar consulta optimizada mediante PowerShell
        ps_cmd = (
            f"Get-NetFirewallRule | Where-Object {{$_.DisplayName -like '*{suffix}*'}} "
            "| Select-Object -ExpandProperty DisplayName"
        )
        code, stdout, _ = self._runner.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd]
        )

        if code == 0:
            rules = {
                line.strip() for line in stdout.splitlines() if line.strip() and suffix in line
            }
            return sorted(rules)

        # 2. Fallback a netsh advfirewall únicamente si PowerShell falló
        code_ns, stdout_ns, _ = self._runner.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
        )
        if code_ns == 0 and stdout_ns:
            rules_ns: set[str] = set()
            for line in stdout_ns.splitlines():
                stripped = line.strip()
                if stripped.startswith("Rule Name:") and suffix in stripped:
                    rule_val = stripped.split("Rule Name:", 1)[1].strip()
                    rules_ns.add(rule_val)
            return sorted(rules_ns)

        return []
