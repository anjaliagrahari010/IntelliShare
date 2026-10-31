from types import SimpleNamespace

import pytest

from security_ai.rules import evaluate_rules


@pytest.mark.parametrize(
    ("action", "event_type", "expected_rule"),
    [
        ("DOWNLOAD_REVOKED", "AUTHENTICATION", "REVOKED_ACCESS"),
        ("DOWNLOAD_EXPIRED", "AUTHENTICATION", "EXPIRED_ACCESS"),
    ],
)
def test_revoked_or_expired_access_triggers_rule(
    action, event_type, expected_rule
):
    log = SimpleNamespace(
        action=action,
        event_type=event_type,
        description="",
        success=True,
    )

    result = evaluate_rules(log, {})

    triggered_ids = {
        rule.get("rule_id") for rule in result["triggered_rules"]
    }
    assert expected_rule in triggered_ids


def test_normal_download_does_not_trigger_access_restriction_rules():
    log = SimpleNamespace(
        action="DOWNLOAD_SUCCESS",
        event_type="AUTHENTICATION",
        description="",
        success=True,
    )

    result = evaluate_rules(log, {})

    triggered_ids = {
        rule.get("rule_id") for rule in result["triggered_rules"]
    }
    assert "REVOKED_ACCESS" not in triggered_ids
    assert "EXPIRED_ACCESS" not in triggered_ids
