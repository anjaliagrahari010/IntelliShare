import math
from datetime import timedelta
from django.utils import timezone
from accounts.models import AuditLog

# Minimum history required to compute a per-user personal baseline
MIN_BASELINE_EVENTS = 10
MIN_BASELINE_SPAN_DAYS = 2

# Global fallback defaults
GLOBAL_BASELINE = {
    "is_custom": False,
    "sample_count": 0,
    "avg_downloads_per_hour": 3.0,
    "std_downloads_per_hour": 2.0,
    "avg_events_per_hour": 6.0,
    "std_events_per_hour": 4.0,
    "max_normal_downloads_burst": 10.0,
}


def get_user_baseline(user):
    """
    Computes a personalized behavioral baseline for a user based on historical audit events.
    If the user has insufficient activity, falls back safely to the global baseline.
    """
    if not user or not user.is_authenticated:
        return GLOBAL_BASELINE.copy()

    now = timezone.now()
    cutoff_history = now - timedelta(days=30)
    # Exclude the immediate last 1 hour to prevent an ongoing attack from distorting the baseline
    cutoff_recent = now - timedelta(hours=1)

    historical_logs = list(
        AuditLog.objects.filter(
            user=user,
            created_at__gte=cutoff_history,
            created_at__lte=cutoff_recent,
        ).order_by("created_at")
    )

    total_events = len(historical_logs)
    if total_events < MIN_BASELINE_EVENTS:
        return GLOBAL_BASELINE.copy()

    span_days = (historical_logs[-1].created_at - historical_logs[0].created_at).total_seconds() / 86400.0
    if span_days < MIN_BASELINE_SPAN_DAYS:
        return GLOBAL_BASELINE.copy()

    # Bucket downloads and events into hour slots
    hour_buckets_events = {}
    hour_buckets_downloads = {}

    for log in historical_logs:
        # Group by (YYYY-MM-DD, HH)
        bucket_key = (
            log.created_at.year,
            log.created_at.month,
            log.created_at.day,
            log.created_at.hour,
        )
        hour_buckets_events[bucket_key] = hour_buckets_events.get(bucket_key, 0) + 1
        if "DOWNLOAD" in (log.action or "").upper():
            hour_buckets_downloads[bucket_key] = hour_buckets_downloads.get(bucket_key, 0) + 1

    active_hours = max(1, len(hour_buckets_events))

    # Event rates
    event_counts = list(hour_buckets_events.values())
    avg_events = sum(event_counts) / float(active_hours)
    var_events = sum((x - avg_events) ** 2 for x in event_counts) / float(active_hours)
    std_events = math.sqrt(var_events)

    # Download rates
    dl_counts = list(hour_buckets_downloads.values()) or [0]
    avg_dl = sum(dl_counts) / float(active_hours)
    var_dl = sum((x - avg_dl) ** 2 for x in dl_counts) / float(active_hours)
    std_dl = math.sqrt(var_dl)

    # Upper normal bound for burst downloads (mean + 3*std, minimum 8)
    max_normal_downloads = max(8.0, avg_dl + (3.0 * std_dl))

    return {
        "is_custom": True,
        "sample_count": total_events,
        "avg_downloads_per_hour": round(avg_dl, 2),
        "std_downloads_per_hour": round(std_dl, 2),
        "avg_events_per_hour": round(avg_events, 2),
        "std_events_per_hour": round(std_events, 2),
        "max_normal_downloads_burst": round(max_normal_downloads, 2),
    }


def is_download_rate_abnormal(user, current_downloads_1h):
    """
    Checks whether current 1-hour download volume exceeds the user's normal baseline.
    Returns: (is_abnormal: bool, reason: str, baseline_info: dict)
    """
    baseline = get_user_baseline(user)
    threshold = baseline["max_normal_downloads_burst"]

    if current_downloads_1h > threshold:
        if baseline["is_custom"]:
            diff_percent = int(((current_downloads_1h - baseline["avg_downloads_per_hour"]) / max(1.0, baseline["avg_downloads_per_hour"])) * 100)
            reason = (
                f"Download volume ({int(current_downloads_1h)} files/hr) is significantly above "
                f"user's historical baseline (avg {baseline['avg_downloads_per_hour']}/hr, +{diff_percent}% deviation)"
            )
        else:
            reason = (
                f"Download burst ({int(current_downloads_1h)} files/hr) exceeds safe system baseline "
                f"threshold ({int(threshold)} files/hr)"
            )
        return True, reason, baseline

    return False, "", baseline
