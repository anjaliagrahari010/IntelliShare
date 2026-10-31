from types import SimpleNamespace

import pytest

from security_ai.rules import evaluate_rules


def make_log(action, description=""):
    return SimpleNamespace(
        action=action,
        event_type="SHARING",
        description=description,
        success=False,
    )


@pytest.mark.parametrize(
    ("action", "description", "features"),
    [
        ("SHARE_PASSWORD_FAILED", "", {}),
        ("OTHER", "Incorrect password entered", {}),
        ("SHARE_PASSWORD_SUCCESS", "", {}),
        ("SHARE_FILE", "", {"shares_1h": 9}),
        ("SHARE_FILE", "", {"shares_1h": 10}),
        ("SHARE_FILE", "", {"shares_1h": 12}),
    ],
)
def test_sharing_rule_evaluation(action, description, features):
    log = make_log(action, description)

    result = evaluate_rules(log, features)

    assert isinstance(result["triggered_rules"], list)
    assert all(
        "rule_id" in rule for rule in result["triggered_rules"]
    )
