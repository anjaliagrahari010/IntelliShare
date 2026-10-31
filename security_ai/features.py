from datetime import timedelta
from django.utils import timezone
from accounts.models import AuditLog

FEATURE_NAMES = [
    "events_5m",
    "events_15m",
    "events_1h",
    "failed_logins_1h",
    "failed_otps_1h",
    "successful_logins_1h",
    "downloads_1h",
    "uploads_1h",
    "shares_1h",
    "access_requests_1h",
    "failed_access_1h",
    "integrity_failures_1h",
    "malware_events_1h",
    "distinct_ips_24h",
    "distinct_devices_24h",
    "auth_failure_ratio",
    "time_since_last_event_sec",
    "different_files_accessed_1h",
    "repeated_resource_access_1h",
]


def extract_features(user=None, ip_address=None, as_of_time=None, exclude_log_id=None):
    """
    Extracts deterministic numerical behavioral features from actual AuditLog records.
    Can extract for an authenticated User, or for an IP address if user is None.
    
    Returns:
        dict: feature_name -> float value
    """
    if as_of_time is None:
        as_of_time = timezone.now()

    # Base queryset
    qs = AuditLog.objects.filter(created_at__lte=as_of_time)
    if exclude_log_id:
        qs = qs.exclude(id=exclude_log_id)

    if user and user.is_authenticated:
        qs = qs.filter(user=user)
    elif ip_address:
        qs = qs.filter(ip_address=ip_address)
    else:
        # Empty context
        return {name: 0.0 for name in FEATURE_NAMES}

    # Time boundaries
    t_5m = as_of_time - timedelta(minutes=5)
    t_15m = as_of_time - timedelta(minutes=15)
    t_1h = as_of_time - timedelta(hours=1)
    t_24h = as_of_time - timedelta(hours=24)

    # 24-hour log cache for efficient aggregate calculations in Python
    recent_logs = list(
    qs.filter(created_at__gte=t_24h)
    .order_by("-created_at")
)

    events_5m = 0
    events_15m = 0
    events_1h = 0
    failed_logins_1h = 0
    failed_otps_1h = 0
    successful_logins_1h = 0
    downloads_1h = 0
    uploads_1h = 0
    shares_1h = 0
    access_requests_1h = 0
    failed_access_1h = 0
    integrity_failures_1h = 0
    malware_events_1h = 0

    ips_24h = set()
    devices_24h = set()
    files_accessed_1h = set()
    resource_counts_1h = {}

    last_event_time = None

    for idx, log in enumerate(recent_logs):
        if idx == 0:
            last_event_time = log.created_at

        if log.ip_address:
            ips_24h.add(log.ip_address)
        if log.user_agent:
            devices_24h.add(log.user_agent)

        action_upper = (log.action or "").upper()
        event_type_upper = (log.event_type or "").upper()

        # 1-hour window features
        if log.created_at >= t_1h:
            events_1h += 1

            if log.created_at >= t_15m:
                events_15m += 1

            if log.created_at >= t_5m:
                events_5m += 1

            # Categorize actions
            if "LOGIN_FAILED" in action_upper or (not log.success and "LOGIN" in action_upper):
                failed_logins_1h += 1
            elif "OTP_FAILED" in action_upper or (not log.success and "OTP" in action_upper):
                failed_otps_1h += 1
            elif "LOGIN" in action_upper or "SIGNIN" in action_upper or "OTP_VERIFIED" in action_upper:
                if log.success:
                    successful_logins_1h += 1

            if "DOWNLOAD" in action_upper:
                downloads_1h += 1
            if "UPLOAD" in action_upper:
                uploads_1h += 1
            if "SHARE" in action_upper:
                shares_1h += 1

            if "ACCESS_REQUEST" in action_upper:
                access_requests_1h += 1

            if (not log.success) or "DENIED" in action_upper or "UNAUTHORIZED" in action_upper or "FAILED" in action_upper or "EXPIRED" in action_upper or "REVOKED" in action_upper:
                failed_access_1h += 1

            if "INTEGRITY" in action_upper or "INTEGRITY" in event_type_upper or "TAMPER" in action_upper:
                if not log.success or "FAILED" in action_upper:
                    integrity_failures_1h += 1

            if "MALWARE" in action_upper or "MALWARE" in event_type_upper:
                malware_events_1h += 1

            # Resource tracking from metadata or description
            resource_key = None
            if isinstance(log.metadata, dict):
                resource_key = log.metadata.get("file_id") or log.metadata.get("file_name")
            if not resource_key and log.description:
                resource_key = log.description[:50]
            if resource_key:
                files_accessed_1h.add(resource_key)
                resource_counts_1h[resource_key] = resource_counts_1h.get(resource_key, 0) + 1

    # Authentication failure ratio
    total_auth = failed_logins_1h + failed_otps_1h + successful_logins_1h
    if total_auth > 0:
        auth_failure_ratio = (failed_logins_1h + failed_otps_1h) / float(total_auth)
    else:
        auth_failure_ratio = 0.0

    # Time since last event in seconds
    if last_event_time:
        time_since_last_event_sec = max(0.0, (as_of_time - last_event_time).total_seconds())
    else:
        time_since_last_event_sec = 86400.0  # Max 1 day default

    # Repeated resource access
       # Repeated resource access
    repeated_resource_access = sum(
        count - 1
        for count in resource_counts_1h.values()
        if count > 1
    )

    return {
        "events_5m": float(events_5m),
        "events_15m": float(events_15m),
        "events_1h": float(events_1h),
        "failed_logins_1h": float(failed_logins_1h),
        "failed_otps_1h": float(failed_otps_1h),
        "successful_logins_1h": float(successful_logins_1h),
        "downloads_1h": float(downloads_1h),
        "uploads_1h": float(uploads_1h),
        "shares_1h": float(shares_1h),
        "access_requests_1h": float(access_requests_1h),
        "failed_access_1h": float(failed_access_1h),
        "integrity_failures_1h": float(integrity_failures_1h),
        "malware_events_1h": float(malware_events_1h),
        "distinct_ips_24h": float(max(1, len(ips_24h))),
        "distinct_devices_24h": float(max(1, len(devices_24h))),
        "auth_failure_ratio": float(auth_failure_ratio),
        "time_since_last_event_sec": float(time_since_last_event_sec),
        "different_files_accessed_1h": float(len(files_accessed_1h)),
        "repeated_resource_access_1h": float(repeated_resource_access),
    }


def features_to_vector(feature_dict):
    """
    Converts feature dictionary into ordered float vector matching FEATURE_NAMES.
    """
    return [float(feature_dict.get(name, 0.0)) for name in FEATURE_NAMES]
