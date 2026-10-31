import pytest

from accounts.models import AuditLog
from security_ai.engine import create_or_update_incident


@pytest.mark.django_db
def test_correlated_events_update_the_same_incident():
    test_ip = "192.0.2.77"

    first_log = AuditLog.objects.create(
        user=None,
        action="MALWARE_DETECTED",
        description="Deduplication test event 1",
        ip_address=test_ip,
        user_agent="IntelliShare-Dedup-Test",
        metadata={},
        success=False,
        event_type="SECURITY",
    )

    first = create_or_update_incident(
        audit_log=first_log,
        incident_type="MALWARE_DETECTED",
        severity="CRITICAL",
        risk_score=95,
        anomaly_score=0.8,
        rule_score=95,
        reasons=["Test malware rule"],
        features={},
    )

    second_log = AuditLog.objects.create(
        user=None,
        action="MALWARE_DETECTED",
        description="Deduplication test event 2",
        ip_address=test_ip,
        user_agent="IntelliShare-Dedup-Test",
        metadata={},
        success=False,
        event_type="SECURITY",
    )

    second = create_or_update_incident(
        audit_log=second_log,
        incident_type="MALWARE_DETECTED",
        severity="CRITICAL",
        risk_score=98,
        anomaly_score=0.9,
        rule_score=95,
        reasons=["Repeated test malware rule"],
        features={},
    )

    assert first.pk == second.pk
    assert second.risk_score >= 95

    evidence = second.evidence or {}
    assert evidence.get("correlation_count", 0) >= 2

    merged_reasons = evidence.get("reasons", [])
    assert "Test malware rule" in merged_reasons
    assert "Repeated test malware rule" in merged_reasons
