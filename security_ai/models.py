from django.db import models
from django.conf import settings
from django.utils import timezone


class SecurityIncident(models.Model):
    INCIDENT_TYPES = [
        ("BRUTE_FORCE", "Brute Force Authentication Attempt"),
        ("OTP_ABUSE", "Repeated OTP Verification Failure"),
        ("MASS_DOWNLOAD", "Mass / Burst File Download Anomaly"),
        ("INTEGRITY_VIOLATION", "Cryptographic Integrity Verification Failure"),
        ("MALWARE_DETECTED", "Malicious Payload Detected by Antivirus"),
        ("REVOKED_EXPIRED_ACCESS", "Access to Revoked / Expired Resource"),
        ("UNAUTHORIZED_ACCESS", "Unauthorized Resource Access Attempt"),
        ("SUSPICIOUS_SHARING", "Anomalous File Sharing Activity"),
        ("IP_DEVICE_ANOMALY", "Unusual IP / Device Origin Switch"),
        ("ISOLATION_FOREST_ANOMALY", "Behavioral Isolation Forest Outlier"),
    ]

    SEVERITY_LEVELS = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]

    STATUS_CHOICES = [
        ("OPEN", "Open"),
        ("INVESTIGATING", "Investigating"),
        ("RESOLVED", "Resolved"),
        ("FALSE_POSITIVE", "False Positive"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="security_incidents",
    )

    incident_type = models.CharField(
        max_length=64,
        choices=INCIDENT_TYPES,
        db_index=True,
    )

    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_LEVELS,
        default="MEDIUM",
        db_index=True,
    )

    risk_score = models.SmallIntegerField(
        default=0,
        help_text="Calculated composite risk score (0-100)",
    )

    anomaly_score = models.FloatField(
        default=0.0,
        help_text="Isolation Forest anomaly score (0.0 to 1.0)",
    )

    rule_score = models.FloatField(
        default=0.0,
        help_text="Deterministic rule-based score (0.0 to 100.0)",
    )

    description = models.TextField()

    evidence = models.JSONField(
        default=dict,
        blank=True,
        help_text="Structured evidence including triggered rules, reasons, and feature values",
    )

    source_event = models.ForeignKey(
        "accounts.AuditLog",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="incidents",
    )

    status = models.CharField(
        max_length=30,
        choices=STATUS_CHOICES,
        default="OPEN",
        db_index=True,
    )

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
    )

    user_agent = models.TextField(
        blank=True,
        null=True,
    )

    device_information = models.JSONField(
        default=dict,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )

    resolved_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="resolved_incidents",
    )

    resolution_notes = models.TextField(
        blank=True,
        default="",
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Security Incident"
        verbose_name_plural = "Security Incidents"

    def __str__(self):
        return f"[{self.severity}] {self.get_incident_type_display()} - User: {self.user or 'Anonymous'} (Score: {self.risk_score})"

    def mark_investigating(self, admin_user=None):
        self.status = "INVESTIGATING"
        self.save(update_fields=["status", "updated_at"])

    def resolve(self, admin_user, notes=""):
        self.status = "RESOLVED"
        self.resolved_by = admin_user
        self.resolved_at = timezone.now()
        self.resolution_notes = notes
        self.save(update_fields=["status", "resolved_by", "resolved_at", "resolution_notes", "updated_at"])

    def mark_false_positive(self, admin_user, notes=""):
        self.status = "FALSE_POSITIVE"
        self.resolved_by = admin_user
        self.resolved_at = timezone.now()
        self.resolution_notes = notes
        self.save(update_fields=["status", "resolved_by", "resolved_at", "resolution_notes", "updated_at"])
