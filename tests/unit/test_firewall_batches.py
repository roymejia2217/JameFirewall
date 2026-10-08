"""Payload-bounded provider batches retain identity and reject uncertain outcomes."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from jame_firewall.core.entities import FirewallRule, ProcessResult, ProcessStatus, RuleDirection
from jame_firewall.core.exceptions import FirewallExecutionError, OperationDeadlineExceeded
from jame_firewall.core.execution import operation_budget
from jame_firewall.core.rule_identity import MANAGED_GROUP, managed_rule_name
from jame_firewall.infrastructure.firewall.netsh_adapter import WindowsNetshAdapter


def rules_for(count: int, component: str = "helper") -> list[FirewallRule]:
    return [
        FirewallRule(
            managed_rule_name(path := Path(f"C:/Apps/{component}{i}.exe"), RuleDirection.OUT),
            path,
            RuleDirection.OUT,
            group=MANAGED_GROUP,
        )
        for i in range(count)
    ]


def responding_runner() -> MagicMock:
    runner = MagicMock()

    def respond(args: list[str], timeout: float | None = None) -> ProcessResult:
        # The payload is data inside a quoted JSON literal, not executable source.
        literal = args[-1].split("$requests = ConvertFrom-Json '", 1)[1].split("';", 1)[0]
        payload = json.loads(literal.replace("''", "'"))
        return ProcessResult(
            ProcessStatus.COMPLETED,
            0,
            json.dumps({"Results": [{"Name": r["Name"], "Succeeded": True} for r in payload]}),
        )

    runner.run.side_effect = respond
    return runner


@pytest.mark.parametrize("method", ["add_rules", "delete_rules"])
def test_rule_count_is_not_capped_and_batches_follow_payload_size(method: str) -> None:
    rules = rules_for(2050)
    runner = responding_runner()
    adapter = WindowsNetshAdapter(runner)
    assert getattr(adapter, method)(rules) == (True,) * len(rules)
    assert runner.run.call_count > 1
    for call in runner.run.call_args_list:
        script = call.args[0][-1]
        assert "Get-NetFirewallRule -PolicyStore PersistentStore -All" in script
        assert "Get-NetFirewallApplicationFilter -PolicyStore PersistentStore -All" in script
        assert "Get-NetFirewallRule -PolicyStore PersistentStore -Name $name" not in script
        assert len(script.encode("utf-16-le")) <= 24000


@pytest.mark.parametrize("method", ["add_rules", "delete_rules"])
def test_empty_batch_never_launches_provider(method: str) -> None:
    runner = responding_runner()
    assert getattr(WindowsNetshAdapter(runner), method)([]) == ()
    runner.run.assert_not_called()


def test_payload_size_also_splits_batches_and_escapes_untrusted_paths() -> None:
    rules = rules_for(3, "A'$(throw 'injection');" + "z" * 1800)
    runner = responding_runner()
    assert WindowsNetshAdapter(runner).add_rules(rules) == (True,) * 3
    assert runner.run.call_count >= 2
    for call in runner.run.call_args_list:
        assert len(call.args[0][-1].encode("utf-16-le")) <= 24000


@pytest.mark.parametrize("method", ["add_rules", "delete_rules"])
def test_invalid_or_duplicate_identity_is_rejected_before_any_mutation(method: str) -> None:
    runner = responding_runner()
    adapter = WindowsNetshAdapter(runner)
    rule = rules_for(1)[0]
    with pytest.raises(FirewallExecutionError):
        getattr(adapter, method)([rule, rule])
    foreign = FirewallRule(rule.name, rule.program_path, rule.direction, group="foreign")
    with pytest.raises(FirewallExecutionError):
        getattr(adapter, method)([rule, foreign])
    runner.run.assert_not_called()


@pytest.mark.parametrize(
    "response",
    [
        "",
        "{}",
        '{"Results": []}',
        '{"Results": [true]}',
        '{"Results": [{"Name": "other", "Succeeded": true}]}',
    ],
)
def test_invalid_batch_response_aborts_without_next_batch(response: str) -> None:
    runner = MagicMock()
    runner.run.return_value = ProcessResult(ProcessStatus.COMPLETED, 0, response)
    with pytest.raises(FirewallExecutionError):
        WindowsNetshAdapter(runner).add_rules(rules_for(9))
    assert runner.run.call_count == 1


def test_known_per_rule_failure_is_retained_in_order() -> None:
    rules = rules_for(2)
    runner = MagicMock()
    runner.run.return_value = ProcessResult(
        ProcessStatus.COMPLETED,
        0,
        json.dumps(
            {
                "Results": [
                    {"Name": rules[0].name, "Succeeded": False},
                    {"Name": rules[1].name, "Succeeded": True},
                ]
            }
        ),
    )
    assert WindowsNetshAdapter(runner).add_rules(rules) == (False, True)


def test_expired_operation_stops_before_next_batch() -> None:
    now = [0.0]
    runner = responding_runner()
    response = runner.run.side_effect

    def expire(args: list[str], timeout: float | None = None) -> ProcessResult:
        result: ProcessResult = response(args, timeout=timeout)
        now[0] = 10
        return result

    runner.run.side_effect = expire
    with operation_budget(10, clock=lambda: now[0]), pytest.raises(OperationDeadlineExceeded):
        WindowsNetshAdapter(runner).add_rules(rules_for(9))
    assert runner.run.call_count == 1


def test_confirmed_batches_renew_operation_window_for_long_total_work() -> None:
    now = [0.0]
    runner = responding_runner()
    response = runner.run.side_effect

    def progress(args: list[str], timeout: float | None = None) -> ProcessResult:
        result: ProcessResult = response(args, timeout=timeout)
        now[0] += 9
        return result

    runner.run.side_effect = progress
    rules = rules_for(3, "z" * 1800)
    with operation_budget(10, clock=lambda: now[0]):
        assert WindowsNetshAdapter(runner).add_rules(rules) == (True,) * len(rules)
    assert runner.run.call_count >= 2
    assert now[0] > 10


@pytest.mark.parametrize(
    "status",
    [
        ProcessStatus.TIMED_OUT,
        ProcessStatus.OUTPUT_LIMIT,
        ProcessStatus.START_FAILED,
        ProcessStatus.IO_FAILED,
    ],
)
def test_incomplete_batch_never_continues_even_with_plausible_json(status: ProcessStatus) -> None:
    runner = responding_runner()
    response = runner.run.side_effect

    def incomplete(args: list[str], timeout: float | None = None) -> ProcessResult:
        valid: ProcessResult = response(args, timeout=timeout)
        return ProcessResult(status, 0, valid.stdout)

    runner.run.side_effect = incomplete
    with pytest.raises(FirewallExecutionError):
        WindowsNetshAdapter(runner).delete_rules(rules_for(9))
    assert runner.run.call_count == 1


@pytest.mark.parametrize("value", [1, "True", None])
def test_per_rule_result_requires_real_boolean(value: object) -> None:
    rules = rules_for(1)
    runner = MagicMock()
    runner.run.return_value = ProcessResult(
        ProcessStatus.COMPLETED,
        0,
        json.dumps({"Results": [{"Name": rules[0].name, "Succeeded": value}]}),
    )
    with pytest.raises(FirewallExecutionError):
        WindowsNetshAdapter(runner).add_rules(rules)


def test_single_oversized_payload_is_rejected_without_launch() -> None:
    runner = responding_runner()
    with pytest.raises(FirewallExecutionError, match="demasiado larga"):
        WindowsNetshAdapter(runner).add_rules(rules_for(1, "z" * 5000))
    runner.run.assert_not_called()


def test_failed_provider_batch_aborts_following_mutations() -> None:
    runner = MagicMock()
    runner.run.return_value = ProcessResult(ProcessStatus.COMPLETED, 1, "", "inventory denied")
    with pytest.raises(FirewallExecutionError, match="incompleto"):
        WindowsNetshAdapter(runner).add_rules(rules_for(9))
    assert runner.run.call_count == 1


def test_provider_failure_is_not_downgraded_to_a_per_rule_failure() -> None:
    runner = responding_runner()
    WindowsNetshAdapter(runner).add_rules(rules_for(1))
    script = runner.run.call_args.args[0][-1]
    assert "Get-NetFirewallRule -PolicyStore PersistentStore -All -ErrorAction Stop" in script
    assert (
        "Get-NetFirewallApplicationFilter -PolicyStore PersistentStore -All -ErrorAction Stop"
        in script
    )
    assert "Incomplete application filter catalog" in script
    assert "catch { $success = $false }" not in script


@pytest.mark.parametrize("method", ["add_rules", "delete_rules"])
def test_batch_uses_indexed_provider_snapshot_instead_of_per_identity_queries(method: str) -> None:
    runner = responding_runner()
    result = getattr(WindowsNetshAdapter(runner), method)(rules_for(8))
    assert result == (True,) * 8
    for call in runner.run.call_args_list:
        script = call.args[0][-1]
        assert "Get-NetFirewallRule -PolicyStore PersistentStore -All" in script
        assert "Get-NetFirewallApplicationFilter -PolicyStore PersistentStore -All" in script
        assert "Get-NetFirewallRule -PolicyStore PersistentStore -Name $name" not in script
        assert "$foundByName.ContainsKey($name)" in script
        assert "$filtersByName.ContainsKey($name)" in script
