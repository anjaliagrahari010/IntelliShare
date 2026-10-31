from django.contrib import admin
from .models import SecurityIncident


@admin.register(SecurityIncident)
class SecurityIncidentAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "incident_type",
        "severity",
        "risk_score",
        "anomaly_score",
        "user",
        "ip_address",
        "status",
        "created_at",
    )
    list_filter = ("severity", "status", "incident_type", "created_at")
    search_fields = ("user__email", "ip_address", "description", "incident_type")
    readonly_fields = ("created_at", "updated_at", "anomaly_score", "rule_score")
