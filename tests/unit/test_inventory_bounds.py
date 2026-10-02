"""Incomplete, oversized and invalid-scope inventories never establish protection."""

import json

import pytest
from tests.unit.test_netsh_adapter import adapter_with_response, inventory_json, rule_json

from jame_firewall.core.exceptions import FirewallExecutionError


@pytest.mark.parametrize(
    "suffixes", [["*"], ["jame'; throw 'x"], ["X"], ["x" * 65], [f"ns-{i}" for i in range(9)]]
)
def test_invalid_or_excessive_namespace_scope_never_launches_provider(suffixes: list[str]) -> None:
    adapter, runner = adapter_with_response(inventory_json())
    with pytest.raises(FirewallExecutionError):
        adapter.list_inventory(suffixes)
    runner.run.assert_not_called()


@pytest.mark.parametrize("complete", [None, False, 1, "True"])
def test_response_requires_explicit_complete_inventory(complete: object) -> None:
    raw = json.loads(inventory_json([rule_json()]))
    raw.pop("Complete", None)
    if complete is not None:
        raw["Complete"] = complete
    adapter, _ = adapter_with_response(json.dumps(raw))
    with pytest.raises(FirewallExecutionError):
        adapter.list_inventory(["jame-block"])


def test_complete_inventory_has_no_fixed_rule_count_ceiling() -> None:
    dto = rule_json()
    rules: list[object] = [{**dto, "Name": f"{dto['Name']}-{index}"} for index in range(2050)]
    adapter, _ = adapter_with_response(inventory_json(rules))
    assert len(adapter.list_inventory(["jame-block"]).rules) == 2050


def test_inventory_queries_stay_scoped_and_fail_closed_before_expensive_filter_reads() -> None:
    adapter, runner = adapter_with_response(inventory_json())
    adapter.list_inventory(["jame-block", "adobe-block"])
    script: str = runner.run.call_args.args[0][-1]
    assert "Read-Candidates 'PersistentStore' 'Group' $group" in script
    assert "Read-Candidates 'PersistentStore' 'Name'" in script
    assert "Read-Candidates 'PersistentStore' 'DisplayName'" in script
    assert "Read-Candidates 'ActiveStore' 'Group' $group" in script
    assert "$maxCandidates" not in script
    assert "$maxRows" not in script
    assert "candidate limit exceeded" not in script
    assert "row limit exceeded" not in script
    assert "Get-NetFirewallRule -PolicyStore PersistentStore)" not in script
    assert "Get-NetFirewallRule -PolicyStore ActiveStore)" not in script
    assert script.index("Read-Candidates 'ActiveStore'") < script.index("$filter = @(")
    # Missing selectors are the sole empty-query exception; provider failures never fall back.
    assert "CmdletizationQuery_NotFound_" in script
    assert "ObjectNotFound" in script
    assert "SilentlyContinue" not in script


def test_activation_submits_more_than_2048_rules_without_arbitrary_rejection() -> None:
    from pathlib import Path
    from unittest.mock import MagicMock

    from tests.fakes.fake_uac import FakeUACAdapter

    from jame_firewall.core.entities import FirewallInventory, RuleDirection, ScanResult
    from jame_firewall.core.rule_identity import managed_rule_name
    from jame_firewall.core.use_cases.block_executables import BlockExecutablesUseCase

    paths = [Path(f"C:/New/helper-{index}.exe") for index in range(1025)]
    scanner = MagicMock()
    scanner.find_executables.return_value = ScanResult(executables=tuple(paths))
    firewall = MagicMock()
    firewall.list_inventory.return_value = FirewallInventory(rules=())
    firewall.add_rules.return_value = (True,) * (len(paths) * 2)
    BlockExecutablesUseCase(firewall, scanner, FakeUACAdapter()).execute([Path("C:/New")])
    submitted = firewall.add_rules.call_args.args[0]
    assert len(submitted) == 2050
    assert submitted[0].name == managed_rule_name(paths[0], RuleDirection.IN)


def test_duplicate_native_identity_case_is_rejected() -> None:
    dto = rule_json()
    adapter, _ = adapter_with_response(inventory_json([dto, {**dto, "Name": dto["Name"].upper()}]))
    with pytest.raises(FirewallExecutionError):
        adapter.list_inventory(["jame-block"])
