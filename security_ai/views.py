from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render

from .models import SecurityIncident


@login_required(login_url="login")
def security_dashboard(request):

    incidents = (
        SecurityIncident.objects
        .filter(user=request.user)
        .select_related("user")
        .order_by("-created_at")
    )

    context = {
        "incidents": incidents[:100],
        "total_incidents": incidents.count(),
        "critical_count": incidents.filter(
            severity="CRITICAL"
        ).count(),
        "high_count": incidents.filter(
            severity="HIGH"
        ).count(),
        "medium_count": incidents.filter(
            severity="MEDIUM"
        ).count(),
        "open_count": incidents.filter(
            status="OPEN"
        ).count(),
    }

    return render(
        request,
        "security_ai/dashboard.html",
        context,
    )


@login_required(login_url="login")
def incident_detail(request, incident_id):

    incident = get_object_or_404(
        SecurityIncident.objects.select_related(
            "user",
            "source_event"
        ),
        id=incident_id,
        user=request.user,
    )

    return render(
        request,
        "security_ai/incident_detail.html",
        {
            "incident": incident
        },
    )