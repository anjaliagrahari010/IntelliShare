from .config import RULE_THRESHOLDS
from .baseline import is_download_rate_abnormal


def evaluate_rules(audit_log, features, user=None):
    """
    Evaluates deterministic security rules on the current audit log and extracted feature state.
    
    Returns:
        dict: {
            "rule_score": float (0.0 to 100.0),
            "triggered_rules": list of dict,
            "reasons": list of str,
            "incident_type": str or None,
            "max_rule_severity": str ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        }
    """
    triggered_rules = []
    reasons = []
    action = (audit_log.action or "").upper()
    event_type = (audit_log.event_type or "").upper()
    description = (audit_log.description or "").lower()

    # 1. Malware Detection (CRITICAL)
    if "MALWARE" in action or "MALWARE" in event_type or "malware" in description:
        triggered_rules.append({
            "rule_id": "MALWARE_DETECTED",
            "name": "Antivirus Malware Detection",
            "severity": "CRITICAL",
            "score": 95.0,
            "reason": "ClamAV detected malicious payload or virus in uploaded file.",
        })
        reasons.append("ClamAV detected a malicious payload in the uploaded file.")

    # 2. Cryptographic Integrity Failure (CRITICAL)
    if "INTEGRITY_FAILED" in action or "AES-GCM" in audit_log.description or "integrity" in description and not audit_log.success:
        triggered_rules.append({
            "rule_id": "INTEGRITY_VIOLATION",
            "name": "Cryptographic Integrity Failure",
            "severity": "CRITICAL",
            "score": 90.0,
            "reason": "Cryptographic verification failed (SHA-256 hash or AES-GCM authentication tag mismatch). Possible tampering or corruption.",
        })
        reasons.append("Cryptographic integrity verification failed (SHA-256 checksum or AES-GCM tag mismatch).")

    # 3. Brute Force Authentication (HIGH)
    failed_logins = int(features.get("failed_logins_1h", 0))
    if ("LOGIN_FAILED" in action or not audit_log.success and "LOGIN" in action) and failed_logins >= RULE_THRESHOLDS["BRUTE_FORCE_FAILED_LOGINS"]:
        score = min(95.0, 60.0 + (failed_logins * 5.0))
        triggered_rules.append({
            "rule_id": "BRUTE_FORCE_LOGIN",
            "name": "Brute Force Authentication",
            "severity": "HIGH",
            "score": score,
            "reason": f"{failed_logins} failed login attempts detected within the activity window.",
        })
        reasons.append(f"{failed_logins} failed login attempts detected in a short period.")
    elif failed_logins >= RULE_THRESHOLDS["BRUTE_FORCE_FAILED_LOGINS"]:
        triggered_rules.append({
            "rule_id": "BRUTE_FORCE_LOGIN",
            "name": "Brute Force Authentication",
            "severity": "HIGH",
            "score": 75.0,
            "reason": f"High frequency of failed logins ({failed_logins} failures recently).",
        })
        reasons.append(f"{failed_logins} failed login attempts recorded recently.")

    # 4. Repeated OTP Failures (HIGH)
    failed_otps = int(features.get("failed_otps_1h", 0))
    if ("OTP_FAILED" in action or "OTP" in action and not audit_log.success) and failed_otps >= RULE_THRESHOLDS["FAILED_OTP_THRESHOLD"]:
        score = min(90.0, 65.0 + (failed_otps * 8.0))
        triggered_rules.append({
            "rule_id": "OTP_ABUSE",
            "name": "Repeated OTP Verification Failures",
            "severity": "HIGH",
            "score": score,
            "reason": f"{failed_otps} failed one-time passcode (OTP) verification attempts.",
        })
        reasons.append(f"{failed_otps} failed OTP attempts recorded in a short period.")

    # 5. Mass / Burst File Downloads (HIGH)
    downloads_1h = features.get("downloads_1h", 0.0)
    if "DOWNLOAD" in action:
        is_abnormal, dl_reason, baseline = is_download_rate_abnormal(user, downloads_1h)
        if is_abnormal:
            triggered_rules.append({
                "rule_id": "MASS_DOWNLOAD",
                "name": "Abnormal File Download Volume",
                "severity": "HIGH",
                "score": 75.0,
                "reason": dl_reason,
            })
            reasons.append(dl_reason)

    # 6. Access to Revoked or Expired Links (HIGH / MEDIUM)
    if "REVOKED" in action or "revoked" in description:
        triggered_rules.append({
            "rule_id": "REVOKED_ACCESS",
            "name": "Access Attempt on Revoked Share",
            "severity": "HIGH",
            "score": 70.0,
            "reason": "Attempted to access or download a revoked share link.",
        })
        reasons.append("Unauthorized attempt to access a revoked file share link.")
    elif "EXPIRED" in action or "expired" in description:
        triggered_rules.append({
            "rule_id": "EXPIRED_ACCESS",
            "name": "Access Attempt on Expired Share",
            "severity": "MEDIUM",
            "score": 50.0,
            "reason": "Attempted to access an expired share link.",
        })
        reasons.append("Attempt to access an expired file share link.")

    # 7. Share Password Failures (MEDIUM)
    if "SHARE_PASSWORD_FAILED" in action or ("password" in description and "incorrect" in description):
        triggered_rules.append({
            "rule_id": "SHARE_PASSWORD_FAILED",
            "name": "Incorrect Share Password",
            "severity": "MEDIUM",
            "score": 45.0,
            "reason": "Incorrect password entered for protected share link.",
        })
        reasons.append("Incorrect password submitted for protected shared file.")

    # 8. Distinct IP Origin Anomaly (MEDIUM)
    distinct_ips = int(features.get("distinct_ips_24h", 1))
    if distinct_ips >= RULE_THRESHOLDS["DISTINCT_IPS_1H_THRESHOLD"]:
        triggered_rules.append({
            "rule_id": "MULTI_IP_ANOMALY",
            "name": "Multiple IP Addresses Detected",
            "severity": "MEDIUM",
            "score": 40.0,
            "reason": f"Activity from {distinct_ips} different IP addresses within 24 hours.",
        })
        reasons.append(f"Account active from {distinct_ips} distinct IP addresses within 24 hours.")

    # 9. Burst Sharing Activity (MEDIUM)
    shares_1h = int(features.get("shares_1h", 0))
    if "SHARE" in action and shares_1h >= RULE_THRESHOLDS["BURST_SHARING_COUNT"]:
        triggered_rules.append({
            "rule_id": "BURST_SHARING",
            "name": "High Volume Sharing Spike",
            "severity": "MEDIUM",
            "score": 50.0,
            "reason": f"Unusually high file sharing activity ({shares_1h} files shared in 1 hour).",
        })
        reasons.append(f"High-frequency file sharing: {shares_1h} files shared in the last hour.")

    # Calculate aggregate rule score (highest rule score + fractional contribution from others)
    if not triggered_rules:
        return {
            "rule_score": 0.0,
            "triggered_rules": [],
            "reasons": [],
            "incident_type": None,
            "max_rule_severity": "LOW",
        }

    # Sort rules descending by score
    sorted_rules = sorted(triggered_rules, key=lambda r: r["score"], reverse=True)
    top_rule = sorted_rules[0]

    # Diminishing returns sum for multiple rules
    combined_score = top_rule["score"]
    for r in sorted_rules[1:]:
        combined_score += (100.0 - combined_score) * (r["score"] / 200.0)

    combined_score = min(100.0, round(combined_score, 1))

    # Incident type mapping
    incident_type_map = {
        "MALWARE_DETECTED": "MALWARE_DETECTED",
        "INTEGRITY_VIOLATION": "INTEGRITY_VIOLATION",
        "BRUTE_FORCE_LOGIN": "BRUTE_FORCE",
        "OTP_ABUSE": "OTP_ABUSE",
        "MASS_DOWNLOAD": "MASS_DOWNLOAD",
        "REVOKED_ACCESS": "REVOKED_EXPIRED_ACCESS",
        "EXPIRED_ACCESS": "REVOKED_EXPIRED_ACCESS",
        "SHARE_PASSWORD_FAILED": "UNAUTHORIZED_ACCESS",
        "MULTI_IP_ANOMALY": "IP_DEVICE_ANOMALY",
        "BURST_SHARING": "SUSPICIOUS_SHARING",
    }

    return {
        "rule_score": combined_score,
        "triggered_rules": triggered_rules,
        "reasons": reasons,
        "incident_type": incident_type_map.get(
        top_rule["rule_id"],
        "ISOLATION_FOREST_ANOMALY",),
        "max_rule_severity": top_rule["severity"],
    }
