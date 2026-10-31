from .models import AuditLog


def get_client_ip(request):
    if not request:
        return None
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def parse_device_information(user_agent_str):
    if not user_agent_str:
        return {"browser": "Unknown", "os": "Unknown"}

    ua = user_agent_str.lower()
    os_name = "Other"
    if "windows" in ua:
        os_name = "Windows"
    elif "macintosh" in ua or "mac os" in ua:
        os_name = "macOS"
    elif "linux" in ua:
        os_name = "Linux"
    elif "android" in ua:
        os_name = "Android"
    elif "iphone" in ua or "ipad" in ua:
        os_name = "iOS"

    browser_name = "Other"
    if "edg" in ua:
        browser_name = "Edge"
    elif "chrome" in ua:
        browser_name = "Chrome"
    elif "firefox" in ua:
        browser_name = "Firefox"
    elif "safari" in ua:
        browser_name = "Safari"
    elif "postman" in ua:
        browser_name = "Postman"
    elif "python" in ua or "requests" in ua:
        browser_name = "Python Client"

    return {"browser": browser_name, "os": os_name, "raw": user_agent_str[:200]}


def infer_event_type(action):
    act = (action or "").strip().upper().replace("-", "_").replace(" ", "_")

    # Security events must be checked first.
    if any(k in act for k in [
        "MALWARE", "INTEGRITY", "TAMPER", "SUSPICIOUS",
        "BRUTE", "ABUSE", "UNAUTHORIZED", "SECURITY_INCIDENT",
    ]):
        return "SECURITY"

    # Authentication events.
    if any(k in act for k in [
        "LOGIN", "LOGOUT", "OTP", "AUTH", "PASSWORD",
        "SIGNIN", "SIGNUP", "ACTIVAT", "REGISTER",
    ]):
        return "AUTHENTICATION"

    # Sharing and access-control events.
    if any(k in act for k in [
        "SHARE", "ACCESS_REQUEST", "ACCESS_DENIED",
        "ACCESS_GRANTED", "REVOK", "EXPIRED",
    ]):
        return "SHARING"

    # File and folder operations.
    if any(k in act for k in [
        "UPLOAD", "DOWNLOAD", "DELETE", "FILE",
        "ENCRYPT", "DECRYPT", "FOLDER", "INTEGRITY",
    ]):
        return "FILE_ACTIVITY"

    # Do not label unknown events as security incidents.
    return "OTHER"



def create_audit_log(
    user=None,
    action="",
    description="",
    request=None,
    event_type=None,
    success=True,
    reason="",
    metadata=None,
    device_information=None,
    risk_level="LOW",
    risk_score=0,
    suspicious=False,
    trigger_evaluation=True,
):
    ip_address = None
    user_agent = None

    if request:
        ip_address = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")

    if device_information is None:
        device_information = parse_device_information(user_agent)

    if metadata is None:
        metadata = {}

    if not event_type:
        event_type = infer_event_type(action)

    audit_log = AuditLog.objects.create(
        user=user if (user and user.is_authenticated) else None,
        action=action,
        description=description,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata=metadata,
        event_type=event_type,
        success=success,
        reason=reason,
        device_information=device_information,
        risk_level=risk_level,
        risk_score=risk_score,
        suspicious=suspicious,
    )

    if trigger_evaluation:
        try:
            from security_ai.engine import evaluate_security_event
            evaluate_security_event(audit_log, request=request)
        except Exception as e:
            # Safe fallback: never disrupt transaction or normal user flow
            print(f"[Audit] Warning: Anomaly detection evaluation failed: {e}")

    return audit_log