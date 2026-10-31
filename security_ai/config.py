from django.conf import settings
import os

# Base directory for persisted models
MODEL_DIR = getattr(
    settings,
    "SECURITY_AI_MODEL_DIR",
    os.path.join(settings.BASE_DIR, "security_ai", "saved_models"),
)

# Isolation Forest Hyperparameters
ISOLATION_FOREST_N_ESTIMATORS = getattr(settings, "SECURITY_AI_N_ESTIMATORS", 100)
ISOLATION_FOREST_CONTAMINATION = getattr(settings, "SECURITY_AI_CONTAMINATION", 0.05)
ISOLATION_FOREST_RANDOM_STATE = getattr(settings, "SECURITY_AI_RANDOM_STATE", 42)
MIN_SAMPLES_FOR_TRAINING = getattr(settings, "SECURITY_AI_MIN_TRAIN_SAMPLES", 10)

# Risk Level Cutoffs (0 to 100)
RISK_LEVEL_LOW_MAX = 29
RISK_LEVEL_MEDIUM_MAX = 59
RISK_LEVEL_HIGH_MAX = 79
# >= 80 is CRITICAL

# Threshold for marking AuditLog suspicious and creating/correlating SecurityIncident
SUSPICIOUS_RISK_THRESHOLD = getattr(settings, "SECURITY_AI_SUSPICIOUS_THRESHOLD", 60)

# Incident Deduplication / Correlation Window (in minutes)
INCIDENT_DEDUPLICATION_MINUTES = getattr(settings, "SECURITY_AI_DEDUP_MINUTES", 30)

# Rule-Based Thresholds
RULE_THRESHOLDS = {
    # Authentication
    "BRUTE_FORCE_FAILED_LOGINS": 5,      # Failed logins in 10m
    "BRUTE_FORCE_WINDOW_MINUTES": 10,
    "FAILED_OTP_THRESHOLD": 3,           # Failed OTP attempts in 10m
    "FAILED_OTP_WINDOW_MINUTES": 10,

    # Downloads
    "MASS_DOWNLOAD_BURST_COUNT": 8,      # Downloads in 10m
    "MASS_DOWNLOAD_BURST_WINDOW_MIN": 10,
    "MASS_DOWNLOAD_BASELINE_MULTIPLIER": 3.0,  # 3x standard hourly download baseline

    # Integrity & Malware
    "INTEGRITY_FAILURE_THRESHOLD": 1,    # SHA-256 or AES-GCM tag mismatch is immediately HIGH/CRITICAL
    "MALWARE_DETECTION_THRESHOLD": 1,    # ClamAV detection is immediately CRITICAL

    # Sharing
    "REVOKED_ACCESS_ATTEMPTS": 2,        # Attempts to access revoked file
    "EXPIRED_ACCESS_ATTEMPTS": 3,        # Attempts to access expired file
    "WRONG_SHARE_PASSWORD_ATTEMPTS": 3,  # Incorrect share password attempts
    "BURST_SHARING_COUNT": 10,           # Files shared in 1 hour

    # Network / Origin
    "DISTINCT_IPS_1H_THRESHOLD": 3,      # Number of distinct IPs for same user in 1 hour
}

# Score Weights for Combined Risk Score
# Final Score = (ML_WEIGHT * ml_score) + (RULE_WEIGHT * rule_score) + base_event_penalty
ML_SCORE_WEIGHT = 0.35
RULE_SCORE_WEIGHT = 0.65
