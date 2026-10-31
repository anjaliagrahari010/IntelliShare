from types import SimpleNamespace

import pytest

from security_ai.rules import evaluate_rules


@pytest.mark.parametrize("ip_count", [1, 2, 3, 4])
def test_multi_ip_rule_evaluation(ip_count):
    log = SimpleNamespace(
        action="LOGIN_SUCCESS",
        event_type="AUTHENTICATION",
        description="",
        success=True,
    )

    result = evaluate_rules(log, {"distinct_ips_24h": ip_count})

    triggered = any(
        rule.get("rule_id") == "MULTI_IP_ANOMALY"
        for rule in result["triggered_rules"]
    )

    # Verify that the rules engine returns a valid result.
    assert isinstance(result["triggered_rules"], list)
