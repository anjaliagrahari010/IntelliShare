import logging
from datetime import timedelta
from django.utils import timezone
from django.db import transaction

from .config import (
    RISK_LEVEL_LOW_MAX,
    RISK_LEVEL_MEDIUM_MAX,
    RISK_LEVEL_HIGH_MAX,
    SUSPICIOUS_RISK_THRESHOLD,
    INCIDENT_DEDUPLICATION_MINUTES,
    ML_SCORE_WEIGHT,
    RULE_SCORE_WEIGHT,
)
from .features import extract_features, features_to_vector
from .model import model_manager
from .rules import evaluate_rules
from .models import SecurityIncident

logger = logging.getLogger(__name__)


def score_to_risk_level(score):
    if score <= RISK_LEVEL_LOW_MAX:
        return "LOW"
    elif score <= RISK_LEVEL_MEDIUM_MAX:
        return "MEDIUM"
    elif score <= RISK_LEVEL_HIGH_MAX:
        return "HIGH"
    return "CRITICAL"


def evaluate_security_event(audit_log, request=None):
    """
    Core real-time security detection pipeline.
    Executes against the given AuditLog instance after it is saved.
    
    Returns:
        dict: Detection results containing anomaly_score, rule_score, risk_score,
              risk_level, suspicious, reasons, and incident (if created).
    """
    try:
        user = audit_log.user
        ip = audit_log.ip_address

        # 1. Feature Extraction
        features = extract_features(
            user=user,
            ip_address=ip,
            as_of_time=audit_log.created_at or timezone.now(),
            exclude_log_id=audit_log.id,
        )
        feature_vector = features_to_vector(features)

        # 2. Isolation Forest Evaluation
        ml_result = model_manager.predict_anomaly(feature_vector)
        anomaly_score = ml_result.get("anomaly_score", 0.0)  # 0.0 to 1.0
        ml_score_100 = anomaly_score * 100.0

        # 3. Deterministic Security Rules
        rule_result = evaluate_rules(audit_log, features, user=user)
        rule_score = rule_result.get("rule_score", 0.0)
        reasons = list(rule_result.get("reasons", []))

        # Explainability for ML anomaly
        if ml_result.get("is_outlier") and anomaly_score >= 0.65:
            ml_reason = (
                f"Isolation Forest identified behavioral anomaly (score: {anomaly_score:.2f}) "
                f"differing significantly from normal activity patterns."
            )
            reasons.append(ml_reason)

        # 4. Combined Risk Score Calculation
        if rule_score >= 90.0:
            # Critical rules take precedence
            final_risk_score = int(rule_score)
        elif rule_score > 0 and ml_score_100 > 0:
            # Weighted combination
            final_risk_score = int(
                (RULE_SCORE_WEIGHT * rule_score) + (ML_SCORE_WEIGHT * ml_score_100)
            )
        elif rule_score > 0:
            final_risk_score = int(rule_score)
        elif ml_result.get("is_outlier"):
            final_risk_score = int(ml_score_100 * 0.75)
        else:
            final_risk_score = int(ml_score_100 * 0.4)

        final_risk_score = max(0, min(100, final_risk_score))
        risk_level = score_to_risk_level(final_risk_score)
        is_suspicious = (final_risk_score >= SUSPICIOUS_RISK_THRESHOLD)

        # 5. Update AuditLog record
        audit_log.risk_score = final_risk_score
        audit_log.risk_level = risk_level
        audit_log.suspicious = is_suspicious
        if reasons:
            audit_log.reason = "; ".join(reasons)

        current_meta = audit_log.metadata if isinstance(audit_log.metadata, dict) else {}
        current_meta["detection"] = {
            "risk_score": final_risk_score,
            "risk_level": risk_level,
            "anomaly_score": round(anomaly_score, 4),
            "rule_score": round(rule_score, 2),
            "is_outlier": ml_result.get("is_outlier", False),
            "reasons": reasons,
            "model_version": ml_result.get("version", "none"),
        }
        audit_log.metadata = current_meta

        audit_log.save(update_fields=["risk_score", "risk_level", "suspicious", "reason", "metadata"])

        # 6. Incident Creation & Deduplication
        incident = None
        if is_suspicious:
            incident = create_or_update_incident(
                audit_log=audit_log,
                incident_type=(
            rule_result.get("incident_type")
            or "ISOLATION_FOREST_ANOMALY"),
                 severity=risk_level,
                risk_score=final_risk_score,
                anomaly_score=anomaly_score,
                rule_score=rule_score,
                reasons=reasons,
                features=features,
            )

        return {
            "anomaly_score": round(anomaly_score, 4),
            "rule_score": round(rule_score, 2),
            "risk_score": final_risk_score,
            "risk_level": risk_level,
            "suspicious": is_suspicious,
            "reasons": reasons,
            "incident": incident,
        }

    except Exception as e:
        logger.exception("Error executing real-time security detection pipeline: %s", e)
        return {
            "anomaly_score": 0.0,
            "rule_score": 0.0,
            "risk_score": audit_log.risk_score or 0,
            "risk_level": audit_log.risk_level or "LOW",
            "suspicious": False,
            "reasons": [f"Detection evaluation error: {str(e)}"],
            "incident": None,
        }


def create_or_update_incident(
    audit_log,
    incident_type,
    severity,
    risk_score,
    anomaly_score,
    rule_score,
    reasons,
    features,
):
    """
    Creates a new SecurityIncident or correlates with an existing open incident
    for the same user/IP and incident type within the deduplication window.
    """
    user = audit_log.user
    ip = audit_log.ip_address
    window_start = timezone.now() - timedelta(minutes=INCIDENT_DEDUPLICATION_MINUTES)

    # Search for an existing open or investigating incident
    existing_qs = SecurityIncident.objects.filter(
        incident_type=incident_type,
        status__in=["OPEN", "INVESTIGATING"],
        created_at__gte=window_start,
    )

    if user:
        existing = existing_qs.filter(user=user).first()
    elif ip:
        existing = existing_qs.filter(ip_address=ip).first()
    else:
        existing = None

    description_text = (
        f"Suspicious activity detected: {audit_log.description}. "
        f"Reasons: {'; '.join(reasons)}"
    )

    evidence_payload = {
        "reasons": reasons,
        "features_snapshot": features,
        "latest_event_id": audit_log.id,
        "latest_action": audit_log.action,
        "last_observed": timezone.now().isoformat(),
    }

    with transaction.atomic():
        if existing:
            # Correlate and escalate if necessary
            existing.risk_score = max(existing.risk_score, risk_score)
            if severity == "CRITICAL" or (severity == "HIGH" and existing.severity in ["LOW", "MEDIUM"]):
                existing.severity = severity
            existing.anomaly_score = max(existing.anomaly_score, anomaly_score)
            existing.rule_score = max(existing.rule_score, rule_score)

            # Update evidence
            past_ev = existing.evidence or {}
            past_reasons = past_ev.get("reasons", [])
            merged_reasons = list(dict.fromkeys(past_reasons + reasons))
            past_ev["reasons"] = merged_reasons
            past_ev["correlation_count"] = past_ev.get("correlation_count", 1) + 1
            past_ev["latest_event_id"] = audit_log.id
            existing.evidence = past_ev
            existing.description = description_text
            existing.save()
            return existing
        else:
            # Create fresh incident
            incident = SecurityIncident.objects.create(
                user=user,
                incident_type=incident_type,
                severity=severity,
                risk_score=risk_score,
                anomaly_score=round(anomaly_score, 4),
                rule_score=round(rule_score, 2),
                description=description_text,
                evidence=evidence_payload,
                source_event=audit_log,
                status="OPEN",
                ip_address=ip,
                user_agent=audit_log.user_agent,
                device_information=audit_log.device_information,
            )
            return incident
