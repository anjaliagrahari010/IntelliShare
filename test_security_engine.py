import pytest

from accounts.models import AuditLog
from security_ai.engine import evaluate_security_event
from security_ai.models import SecurityIncident


@pytest.mark.django_db
def test_malware_event_is_flagged_and_logged():
    log = AuditLog.objects.create(
        user=None,
        action="MALWARE_DETECTED",
        description="Test malware detection",
        ip_address="192.0.2.10",
        user_agent="IntelliShare-Test",
        metadata={},
        success=False,
        event_type="SECURITY",
    )

    result = evaluate_security_event(log)

    assert result["risk_score"] >= 0
    assert result["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert result["suspicious"] is True
    assert result["incident"] is not None
    assert result["incident"].incident_type == "MALWARE_DETECTED"
    assert SecurityIncident.objects.filter(pk=result["incident"].pk).exists()
