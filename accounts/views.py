import os
import random
import tempfile
from datetime import timedelta
from django.urls import reverse
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, get_user_model, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from .models import *
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Sum
from django.http import HttpResponse, FileResponse
from django.utils import timezone
from django.shortcuts import get_object_or_404
from accounts.models import SecureShareLink
from encryption.utils import decrypt_file
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator, PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_str, force_bytes
from django.contrib.sites.shortcuts import get_current_site
from encryption.rsa_utils import generate_rsa_key_pair
from encryption.key_manager import save_keys
from .utils import format_size
from accounts.audit import create_audit_log
from accounts.email_utils import send_email_async
from .forms import ProfileUpdateForm
from encryption.hash_utils import generate_sha256


# Create your views here.
def home(request):
    return render(request, 'home.html')


def about(request):
    return render(request, 'about.html')


def signup(request):
    if request.method == "POST":
        full_name = request.POST.get("full_name")
        email = request.POST.get("email")
        phone_number = request.POST.get("phone_number")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect("signup")
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return redirect("signup")

        user = User.objects.create_user(
            email=email,
            password=password,
            full_name=full_name,
            phone_number=phone_number)
        user.is_active = False
        user.save()
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        current_site = get_current_site(request)

        verification_link = (f"http://{current_site.domain}/accounts/activate/{uid}/{token}/")

        send_email_async(
            subject="Verify Your VaultShare Account",
            message=f"Click the link below to verify your email:\n\n{verification_link}",
            recipient=user.email,
        )

        messages.success(request, "Account created successfully. Please Verify Your Account via email. ")

        private_key, public_key = generate_rsa_key_pair()
        save_keys(user.id, private_key, public_key)

        return redirect("login")

    return render(request, "signup.html")


def activate(request, uid, token):
    try:
        uid = force_str(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()

        create_audit_log(
            user=user,
            action="ACCOUNT_VERIFIED",
            description="Email verified and account activated successfully",
            request=request,
            event_type="AUTHENTICATION",
            success=True,
        )

        messages.success(
            request,
            "Your email has been verified successfully. You can now log in."
        )
        return redirect("login")

    create_audit_log(
        user=None,
        action="ACTIVATION_FAILED",
        description="Invalid or expired account activation token accessed",
        request=request,
        event_type="AUTHENTICATION",
        success=False,
    )
    messages.error(request, "Verification link is invalid or has expired.")
    return redirect("signup")


def signin(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        user = authenticate(
            request,
            username=email,
            password=password
        )

        if user is not None:

            # Delete old OTPs
            LoginOTP.objects.filter(user=user).delete()

            # Generate 6-digit OTP
            otp = str(random.randint(100000, 999999))

            # Save OTP
            LoginOTP.objects.create(
                user=user,
                otp=otp,
                expires_at=timezone.now() + timedelta(minutes=5)
            )

            # Send OTP email
            send_email_async(
                subject="VaultShare Login Verification",
                message=f"""
Hello {user.first_name},

Your OTP for VaultShare login is:

{otp}

This OTP is valid for 5 minutes.

Do not share this OTP with anyone.

Regards,
VaultShare Team
                """,
                recipient=user.email,
            )

            # Store user ID in session
            request.session["otp_user_id"] = user.id

            messages.success(request, "OTP has been sent to your email.")

            return redirect("verify_otp")

        # Record failed login attempt
        failed_user = User.objects.filter(email=email).first()
        create_audit_log(
            user=failed_user,
            action="LOGIN_FAILED",
            description=f"Failed login attempt for '{email}': Invalid email or password",
            request=request,
            event_type="AUTHENTICATION",
            success=False,
            metadata={"attempted_email": email},
        )
        messages.error(request, "Invalid Email or Password")

    # NOTE: this previously rendered "verify_otp.html", which meant the login
    # page itself served the OTP-entry template. Changed to "login.html" —
    # swap in whatever your actual email/password login template is named.
    return render(request, "login.html")


def logout_view(request):
    if request.user.is_authenticated:
        create_audit_log(
            user=request.user,
            action="LOGOUT",
            description=f"User {request.user.email} logged out successfully",
            request=request,
            event_type="AUTHENTICATION",
            success=True,
        )
    logout(request)
    return redirect('home')


@login_required
def user_dashboard(request):
    files = File.objects.filter(owner=request.user)
    folders = Folder.objects.filter(owner=request.user)
    total_files = files.count()
    total_folders = folders.count()
    shared_files = SharedFile.objects.filter(shared_by=request.user).count()
    used_storage = files.aggregate(total=Sum("file_size"))["total"] or 0
    total_storage = 5 * 1024 * 1024 * 1024
    remaining_storage = total_storage - used_storage
    percent_used = (used_storage / total_storage) * 100
    percent_used = round(percent_used, 2)
    display_percent = max(percent_used, 1) if used_storage > 0 else 0

    context = {
        "folders": folders,
        "files": files,
        "recent_files": files.order_by("-uploaded_at")[:5],
        "total_files": total_files,
        "total_folders": total_folders,
        "shared_files": shared_files,
        "used_storage": format_size(used_storage),
        "remaining_storage": format_size(remaining_storage),
        "total_storage": format_size(total_storage),
        "percent_used": round(percent_used, 2),
        "display_percent": display_percent,
    }
    return render(request, "userDash.html", context)


@login_required
def share_file(request, file_id):
    file = get_object_or_404(File, id=file_id, owner=request.user)
    if request.method == "POST":
        email = request.POST.get("email")
        permission = request.POST.get("permission")
        expires = request.POST.get("expires_at") or None
        shared = SharedFile.objects.create(
            file=file,
            shared_by=request.user,
            receiver_email=email,
            permission=permission,
            expires_at=expires
        )
        link = request.build_absolute_uri(reverse("receiver_download", args=[shared.share_token]))
        send_mail(
            subject="VaulShare File Sharing",
            message=f"""You receive  a secure file.
                  Hello,

{request.user.email} has shared a file with you.

File Name: {file.file_name}

Permission: {permission}

Download Link:
{link}

Regards,
VaultShare
""",
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[email],
            fail_silently=False,
        )
        create_audit_log(
            user=request.user,
            action="FILE_SHARED",
            description=f"File shared: {file.file_name}",
            request=request,
            event_type="FILE_ACTIVITY",
            success=True,
            metadata={
                "file_id": file.id,
                "file_name": file.file_name
            }
        )
    return redirect("myfiles")


def share_download(request, token):

    share = get_object_or_404(
        SecureShareLink,
        token=token,
        is_active=True
    )

    if share.expires_at and timezone.now() > share.expires_at:
        return HttpResponse("This share link has expired.")

    file = share.file

    encrypted_path = file.file.path

    temp_dir = os.path.join(
        settings.MEDIA_ROOT,
        "temp_download"
    )

    os.makedirs(
        temp_dir,
        exist_ok=True
    )

    # Use a unique temp filename to avoid collisions between concurrent
    # downloads of files that share the same original name.
    fd, decrypted_path = tempfile.mkstemp(
        dir=temp_dir,
        suffix=f"_{file.file_name}"
    )
    os.close(fd)

    decrypt_file(
        encrypted_path,
        decrypted_path,
        file.encrypted_key
    )

    # -------------------------------
    # SHA-256 INTEGRITY VERIFICATION
    # -------------------------------

    current_hash = generate_sha256(decrypted_path)

    audit_user = (
        request.user
        if request.user.is_authenticated
        else None
    )

    if current_hash != file.sha256_hash:

        create_audit_log(
            user=audit_user,
            action="INTEGRITY_FAILURE",
            description=f"Integrity verification failed for {file.file_name}",
            request=request,
            event_type="FILE_SECURITY",
            success=False,
            reason="Stored SHA-256 hash does not match current file hash",
            metadata={
                "file_id": file.id,
                "file_name": file.file_name,
                "expected_hash": file.sha256_hash,
                "current_hash": current_hash,
            }
        )

        if os.path.exists(decrypted_path):
            os.remove(decrypted_path)

        return HttpResponse(
            "File integrity verification failed. Download blocked.",
            status=403
        )

    # -------------------------------
    # HASH MATCHED
    # -------------------------------

    create_audit_log(
        user=audit_user,
        action="FILE_DOWNLOADED",
        description=f"Downloaded file: {file.file_name}",
        request=request,
        event_type="FILE_ACTIVITY",
        success=True,
        metadata={
            "file_id": file.id,
            "file_name": file.file_name,
            "integrity_verified": True,
        }
    )

    response = FileResponse(
        open(decrypted_path, "rb"),
        as_attachment=True,
        filename=file.file_name
    )
    # Clean up the plaintext temp file from disk once the response has
    # finished streaming, instead of leaving it there indefinitely.
    response._resource_closers.append(lambda: os.remove(decrypted_path) if os.path.exists(decrypted_path) else None)

    return response


def verify_otp(request):

    user_id = request.session.get("otp_user_id")

    if not user_id:
        messages.error(request, "Session expired. Please login again.")
        return redirect("login")

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        request.session.pop("otp_user_id", None)
        messages.error(
            request,
            "User account not found. Please login again."
        )
        return redirect("login")

    if request.method == "POST":

        entered_otp = request.POST.get("otp")

        try:
            otp_record = LoginOTP.objects.filter(
                user=user,
                is_verified=False
            ).latest("created_at")

        except LoginOTP.DoesNotExist:
            messages.error(request, "OTP not found.")
            return redirect("login")

        if otp_record.is_expired():
            create_audit_log(
                user=user,
                action="OTP_FAILED",
                description=f"OTP verification failed for {user.email}: Passcode expired",
                request=request,
                event_type="AUTHENTICATION",
                success=False,
            )
            messages.error(request, "OTP has expired.")
            otp_record.delete()
            return redirect("login")

        if otp_record.otp != entered_otp:
            create_audit_log(
                user=user,
                action="OTP_FAILED",
                description=f"OTP verification failed for {user.email}: Invalid passcode submitted",
                request=request,
                event_type="AUTHENTICATION",
                success=False,
                metadata={"entered_length": len(entered_otp) if entered_otp else 0},
            )
            messages.error(request, "Invalid OTP.")
            return render(request, "verify_otp.html")

        otp_record.is_verified = True
        otp_record.save()

        login(request, user)

        request.session.pop("otp_user_id", None)
        create_audit_log(
            user=user,
            action="OTP_VERIFIED",
            description="OTP verified successfully",
            request=request,
            event_type="AUTHENTICATION",
            success=True,
        )
        create_audit_log(
            user=user,
            action="LOGIN_SUCCESS",
            description=f"User {user.email} logged in successfully via 2FA OTP",
            request=request,
            event_type="AUTHENTICATION",
            success=True,
        )
        return redirect("user_dashboard")

    return render(request, "verify_otp.html")


def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get("email")
        User = get_user_model()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            create_audit_log(
                user=None,
                action="PASSWORD_RESET_FAILED",
                description=f"Password reset requested for non-existent account: {email}",
                request=request,
                event_type="AUTHENTICATION",
                success=False,
                metadata={"attempted_email": email},
            )
            messages.error(request, "Account Doesn't Exist.")
            return redirect("forgot_password")
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetTokenGenerator().make_token(user)
        reset_link = request.build_absolute_uri(reverse("reset_password", kwargs={"uidb64": uid, "token": token, }))
        send_email_async(
            subject="VaultShare Password Reset",
            message=f"""Hello {user.full_name},

We received a request to reset your VaultShare password. Click the link below:
{reset_link}

If you didn't request this, you can safely ignore this email.

Regards,
VaultShare Team""",
            recipient=user.email,
        )
        create_audit_log(
            user=user,
            action="PASSWORD_RESET_REQUESTED",
            description=f"Password reset link sent to {user.email}",
            request=request,
            event_type="AUTHENTICATION",
            success=True,
        )
        messages.success(request, "Password Reset link has been sent to your email.", )
        return redirect("login")
    return render(request, "forgot_password.html")


@login_required
def profile(request):
    return render(request, 'profile.html')


@login_required
def audit_trail(request):

    logs = AuditLog.objects.filter(
        user=request.user
    )

    return render(request, "audit-trail.html", {"logs": logs})


@login_required
def edit_profile(request):

    if request.method == "POST":
        form = ProfileUpdateForm(
            request.POST,
            instance=request.user
        )

        if form.is_valid():
            form.save()

            messages.success(
                request,
                "Your profile has been updated successfully."
            )

            return redirect("profile")

    else:
        form = ProfileUpdateForm(instance=request.user)

    return render(
        request,
        "edit_profile.html",
        {"form": form}
    )


@login_required
def change_password(request):

    if request.method == "POST":

        form = PasswordChangeForm(
            request.user,
            request.POST
        )

        if form.is_valid():

            user = form.save()

            update_session_auth_hash(request, user)
            create_audit_log(user=user, action="PASSWORD_CHANGE", description="User updated account password", request=request)

            messages.success(
                request,
                "Your password has been changed successfully."
            )

            return redirect("profile")

    else:

        form = PasswordChangeForm(request.user)

    return render(
        request,
        "change_password.html",
        {"form": form}
    )
