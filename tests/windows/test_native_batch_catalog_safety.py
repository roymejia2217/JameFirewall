"""Fail-closed native PowerShell catalog scenarios without modifying firewall policy."""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from jame_firewall.core.entities import FirewallRule, ProcessResult, ProcessStatus, RuleDirection
from jame_firewall.core.rule_identity import MANAGED_GROUP, managed_rule_name
from jame_firewall.infrastructure.firewall.netsh_adapter import WindowsNetshAdapter
from jame_firewall.infrastructure.os.process_runner import SystemProcessRunner

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(sys.platform != "win32", reason="native PowerShell required"),
]


@pytest.mark.parametrize("scenario", ["foreign", "duplicate", "missing-filter", "denied"])
def test_native_batch_catalog_fail_closed_without_policy_mutation(
    scenario: str,
) -> None:
    path = Path("C:/Fixtures/jame-batch-probe.exe")
    suffix = "jame-batch-probe"
    name = managed_rule_name(path, RuleDirection.OUT, suffix)
    rule = FirewallRule(name, path, RuleDirection.OUT, group=MANAGED_GROUP)
    capture = MagicMock()
    capture.run.return_value = ProcessResult(
        ProcessStatus.COMPLETED,
        0,
        json.dumps({"Results": [{"Name": name, "Succeeded": True}]}),
    )
    assert WindowsNetshAdapter(capture).add_rules([rule]) == (True,)
    native_script: str = capture.run.call_args.args[0][-1]

    # PowerShell command discovery resolves these in-process test functions
    # before their namesake NetSecurity cmdlets. Mutation always raises.
    mocked_provider = """
$script:scenario = '__SCENARIO__'
$script:target = '__TARGET__'
$script:program = 'C:\\Fixtures\\jame-batch-probe.exe'
function Get-NetFirewallRule {
    param([string]$PolicyStore, [switch]$All)
    if ($script:scenario -eq 'denied') { throw 'fixture provider denied' }
    $group = if ($script:scenario -eq 'foreign') { 'Foreign' } else { 'JameFirewall.v1' }
    $item = [PSCustomObject]@{
        Name = $script:target
        Group = $group
        Direction = 'Outbound'
    }
    if ($script:scenario -eq 'duplicate') { $item; $item } else { $item }
}
function Get-NetFirewallApplicationFilter {
    param([string]$PolicyStore, [switch]$All)
    if ($script:scenario -ne 'missing-filter') {
        [PSCustomObject]@{ InstanceID = $script:target; Program = $script:program }
    }
}
function New-NetFirewallRule { throw 'Unexpected write on fail-closed probe' }
function Remove-NetFirewallRule { throw 'Unexpected delete on fail-closed probe' }
""".replace("__SCENARIO__", scenario).replace("__TARGET__", name.replace("'", "''"))

    executed = SystemProcessRunner().run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            mocked_provider + native_script,
        ],
        timeout=30,
    )
    assert executed.status == ProcessStatus.COMPLETED, executed
    if scenario == "foreign":
        assert executed.returncode == 0, executed
        assert json.loads(executed.stdout)["Results"] == [{"Name": name, "Succeeded": False}]
    else:
        assert executed.returncode == 1, executed
        assert {
            "duplicate": "Ambiguous rule identity",
            "missing-filter": "Incomplete application filter catalog",
            "denied": "fixture provider denied",
        }[scenario] in executed.stderr
