from django.urls import path
from . import views

app_name = "security_ai"

urlpatterns = [
    path(
        "dashboard/",
        views.security_dashboard,
        name="security_dashboard",
    ),

    path(
        "incident/<int:incident_id>/",
        views.incident_detail,
        name="incident_detail",
    ),
]