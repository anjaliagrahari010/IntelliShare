import os,uuid
from django.shortcuts import render
from django.urls import reverse
import secrets
from django.db import transaction
from encryption.hash_utils import generate_sha256
from django.conf import settings
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import FileResponse, JsonResponse, request
from accounts.models import File, SharedFile, Notification, AccessRequest
from .forms import FileUploadForm
from accounts.models import File, Folder, SecureShareLink
from django.contrib.auth import get_user_model
from django.utils.dateparse import parse_datetime
from pathlib import Path
from datetime import timedelta
from django.utils import timezone
from encryption.key_manager import load_public_key, load_private_key
from encryption.rsa_utils import encrypt_aes_key, decrypt_aes_key
from encryption.aes_utils import encrypt_file, decrypt_file
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from cryptography.exceptions import InvalidTag
from accounts.email_utils import send_email_async
from files.utils import generate_random_password
from accounts.audit import create_audit_log
from accounts.antivirus.clamav import scan_file
User = get_user_model()


@login_required
@login_required
def upload_file(request):

    if request.method == "POST":

        uploaded_file = request.FILES["file"]

        folder = request.POST.get("folder")
        encryption = request.POST.get("encryption_type")
        expiry = request.POST.get("expiry")

        # Validate encryption type before creating encrypted data
        if encryption not in ["AES256", "Dual"]:
            messages.error(request, "Invalid encryption type.")
            return redirect("myfiles")

        temp_dir = os.path.join(
            settings.MEDIA_ROOT,
            "temp"
        )
        os.makedirs(temp_dir, exist_ok=True)

        # Prevent unsafe filenames
        safe_filename = os.path.basename(
            uploaded_file.name
        )

        # Generate unique ID to prevent filename collisions
        unique_id = uuid.uuid4().hex

        # Unique temporary plaintext file
        temp_filename = f"{unique_id}_{safe_filename}"

        file_path = os.path.join(
            temp_dir,
            temp_filename
        )

        encrypted_dir = os.path.join(
            settings.MEDIA_ROOT,
            "encrypted_files"
        )
        os.makedirs(encrypted_dir, exist_ok=True)

        # Unique encrypted .vault file
        encrypted_filename = (
            f"{unique_id}_{safe_filename}.vault"
        )

        encrypted_path = os.path.join(
            encrypted_dir,
            encrypted_filename
        )

        encrypted_file_created = False

        try:

            # Save original file temporarily
            with open(file_path, "wb+") as destination:

                for chunk in uploaded_file.chunks():
                    destination.write(chunk)

            # ClamAV Virus Scan
            is_clean, scan_message = scan_file(
                file_path
            )

            print(
                "ClamAV Result:",
                scan_message
            )

            if not is_clean:

                create_audit_log(
                    user=request.user,
                    action="MALWARE_DETECTED",
                    description=(
                        f"Malware detected during upload: "
                        f"{uploaded_file.name}"
                    ),
                    request=request,
                    event_type="FILE_SECURITY",
                    success=False,
                    reason="ClamAV reported malicious content",
                    metadata={
                        "file_name": uploaded_file.name,
                        "scan_message": scan_message,
                    }
                )

                messages.error(
                    request,
                    f"Upload Rejected: {scan_message}"
                )

                return redirect("myfiles")

            print("ClamAV: File is clean.")

            # Generate SHA-256 of original plaintext
            hash_value = generate_sha256(
                file_path
            )

            print(
                "Generated Hash:",
                hash_value
            )

            print(
                "Length:",
                len(hash_value)
            )

            # Encrypt file using AES-256-GCM
            aes_key, nonce = encrypt_file(
                file_path,
                encrypted_path
            )

            encrypted_file_created = True

            # Store encryption key
            if encryption == "AES256":

                stored_key = aes_key

            elif encryption == "Dual":

                public_key = load_public_key(
                    request.user.id
                )

                stored_key = encrypt_aes_key(
                    public_key,
                    aes_key
                )

            # Relative media path
            relative_path = os.path.relpath(
                encrypted_path,
                settings.MEDIA_ROOT
            ).replace("\\", "/")

            # Save database record
            File.objects.create(
                owner=request.user,
                folder_id=folder if folder else None,
                file_name=safe_filename,
                file=relative_path,
                file_size=uploaded_file.size,
                encryption_type=encryption,
                encrypted_key=stored_key,
                nonce=nonce,
                sha256_hash=hash_value,
            )

            create_audit_log(
                user=request.user,
                action="FILE_UPLOADED",
                description=(
                    f"File uploaded successfully: "
                    f"{safe_filename}"
                ),
                request=request,
                event_type="FILE_ACTIVITY",
                success=True,
                metadata={
                    "file_name": safe_filename,
                    "file_size": uploaded_file.size,
                    "encryption_type": encryption,
                }
            )

            messages.success(
                request,
                "File scanned, encrypted and uploaded successfully."
            )

            return redirect("myfiles")

        except Exception as e:

            print(
                "Upload Error:",
                str(e)
            )

            # Remove encrypted orphan file if it was created
            if encrypted_file_created:
                if os.path.exists(encrypted_path):
                    try:
                        os.remove(encrypted_path)
                    except OSError:
                        pass

            messages.error(
                request,
                "File upload failed. Please try again."
            )

            return redirect("myfiles")

        finally:

            # Always remove plaintext temporary file
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError:
                    pass

    folders = Folder.objects.filter(
        owner=request.user
    )

    return render(
        request,
        "files/upload.html",
        {"folders": folders}
    )

@login_required
def myfiles(request):

    files = File.objects.filter(owner=request.user).order_by("-uploaded_at")

    return render(request, "files/myfiles.html", {"files": files})


@login_required
@login_required
def delete_file(request, file_id):
    file = get_object_or_404(
        File,
        id=file_id,
        owner=request.user
    )

    file.delete()

    return redirect('myfiles')


@login_required
def download_file(request, file_id):
    file = get_object_or_404(
        File,
        id=file_id,
        owner=request.user
    )

    encrypted_path = file.file.path

    if not os.path.exists(encrypted_path):
        messages.error(
            request,
            "The encrypted file could not be found."
        )
        return redirect("myfiles")

    temp_dir = os.path.join(
        settings.MEDIA_ROOT,
        "temp_download"
    )
    os.makedirs(temp_dir, exist_ok=True)

    decrypted_path = os.path.join(
        temp_dir,
        file.file_name
    )

    try:
        # Recover AES key
        if file.encryption_type == "AES256":
            aes_key = bytes(file.encrypted_key)

        elif file.encryption_type == "Dual":
            private_key = load_private_key(request.user.id)
            aes_key = decrypt_aes_key(
                private_key,
                bytes(file.encrypted_key)
            )

        else:
            messages.error(
                request,
                "Unsupported encryption type."
            )
            return redirect("myfiles")

        # Validate encryption metadata
        if len(aes_key) != 32:
            raise ValueError("Invalid AES-256 key length.")

        if not file.nonce:
            raise ValueError("Missing encryption nonce.")

        nonce = bytes(file.nonce)

        if len(nonce) != 12:
            raise ValueError("Invalid AES-GCM nonce length.")

        # AES-GCM decryption
        decrypt_file(
            encrypted_path,
            decrypted_path,
            aes_key,
            nonce
        )

        # SHA-256 verification
        calculated_hash = generate_sha256(
            decrypted_path
        )

        if file.sha256_hash:
            if calculated_hash.lower() != file.sha256_hash.lower():

                create_audit_log(
                    user=request.user,
                    action="FILE_INTEGRITY_FAILED",
                    description=(
                        f"Integrity verification failed for "
                        f"'{file.file_name}'."
                    ),
                    request=request,
                )

                if os.path.exists(decrypted_path):
                    os.remove(decrypted_path)

                messages.error(
                    request,
                    "Download blocked. File integrity verification failed."
                )
                return redirect("myfiles")

        # Successful integrity verification
        create_audit_log(
            user=request.user,
            action="FILE_DOWNLOAD",
            description=(
                f"Downloaded '{file.file_name}' "
                f"after successful integrity verification."
            ),
            request=request,
        )

        response = FileResponse(
            open(decrypted_path, "rb"),
            as_attachment=True,
            filename=file.file_name
        )

        return response

    except InvalidTag:
        if os.path.exists(decrypted_path):
            os.remove(decrypted_path)

        create_audit_log(
            user=request.user,
            action="FILE_INTEGRITY_FAILED",
            description=(
                f"AES-GCM authentication failed for "
                f"'{file.file_name}'. Possible corruption or tampering."
            ),
            request=request,
        )

        messages.error(
            request,
            "Download blocked. The file is corrupted or has been modified."
        )
        return redirect("myfiles")

    except Exception:
        if os.path.exists(decrypted_path):
            os.remove(decrypted_path)

        create_audit_log(
            user=request.user,
            action="FILE_DOWNLOAD_FAILED",
            description=(
                f"Secure download failed for '{file.file_name}'."
            ),
            request=request,
        )

        messages.error(
            request,
            "Unable to securely decrypt this file."
        )
        return redirect("myfiles")

@login_required
def my_folders(request):
    folders = Folder.objects.filter(owner=request.user).order_by("-created_at")
    return render(request, "files/my_folders.html", {"folders": folders})


@login_required
def create_folder(request):
    if request.method == "POST":
        folder_name = request.POST.get("folder_name")
        if folder_name:
            Folder.objects.create(owner=request.user, name=folder_name)

            messages.success(request, "Folder Created Successfully.")
    return redirect("my_folders")


@login_required
def folder_details(request, folder_id):
    folder = get_object_or_404(Folder, id=folder_id, owner=request.user)
    files = File.objects.filter(folder=folder, owner=request.user).order_by(
        "-uploaded_at"
    )
    return render(
        request, "files/folder_detail.html", {"folder": folder, "files": files}
    )


@login_required
def delete_folder(request, folder_id):
    folder = get_object_or_404(Folder, id=folder_id, owner=request.user)
    folder.delete()
    messages.success(request, "Folder deleted successfully.")
    return redirect("my_folders")



@login_required
def upload_to_folder(request, folder_id):

    folder = get_object_or_404(
        Folder,
        id=folder_id,
        owner=request.user
    )

    if request.method == "POST":

        uploaded_file = request.FILES.get("file")
        encryption = request.POST.get("encryption_type")

        if not uploaded_file:
            messages.error(request, "Please select a file.")
            return redirect(
                "folder_detail",
                folder_id=folder.id
            )

        # Safe filename
        safe_filename = os.path.basename(
            uploaded_file.name

        )
        unique_id = uuid.uuid4().hex

        temp_dir = os.path.join(
            settings.MEDIA_ROOT,
            "temp"
        )
        os.makedirs(temp_dir, exist_ok=True)

        file_path = os.path.join(
        temp_dir,
        f"{unique_id}_{safe_filename}"
)

        try:
            # Save temporary plaintext
            with open(file_path, "wb+") as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)

            # ClamAV scan
            is_clean, scan_message = scan_file(
                file_path
            )

            print(
                "ClamAV Result:",
                scan_message
            )

            if not is_clean:
                messages.error(
                    request,
                    f"Upload rejected: {scan_message}"
                )
                return redirect(
                    "folder_detail",
                    folder_id=folder.id
                )

            # SHA-256 of original plaintext
            hash_value = generate_sha256(
                file_path
            )

            # Encryption directory
            encrypted_dir = os.path.join(
                settings.MEDIA_ROOT,
                "encrypted_files"
            )
            os.makedirs(
                encrypted_dir,
                exist_ok=True
            )

            encrypted_filename = (
                f"{unique_id}_{safe_filename}.vault"
            )

            encrypted_path = os.path.join(
                encrypted_dir,
                encrypted_filename
            )

            # AES-256-GCM encryption
            aes_key, nonce = encrypt_file(
                file_path,
                encrypted_path
            )

            # Store AES key
            if encryption == "AES256":

                stored_key = aes_key

            elif encryption == "Dual":

                public_key = load_public_key(
                    request.user.id
                )

                stored_key = encrypt_aes_key(
                    public_key,
                    aes_key
                )

            else:

                messages.error(
                    request,
                    "Invalid encryption type."
                )

                return redirect(
                    "folder_detail",
                    folder_id=folder.id
                )

            # Relative media path
            relative_path = os.path.relpath(
                encrypted_path,
                settings.MEDIA_ROOT
            ).replace("\\", "/")

            # Save database record
            File.objects.create(
                owner=request.user,
                folder=folder,
                file_name=safe_filename,
                file=relative_path,
                file_size=uploaded_file.size,
                encryption_type=encryption,
                encrypted_key=stored_key,
                nonce=nonce,
                sha256_hash=hash_value,
            )

            create_audit_log(
                user=request.user,
                action="upload_file",
                description=(
                    f"Uploaded file to folder: "
                    f"{safe_filename}"
                ),
                request=request,
            )

            messages.success(
                request,
                "File scanned, encrypted and uploaded successfully."
            )

        except Exception:
            # Don't expose internal cryptographic/system errors
            messages.error(
                request,
                "File upload failed. Please try again."
            )

        finally:
            # Always remove plaintext temporary file
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError:
                    pass

    return redirect(
        "folder_detail",
        folder_id=folder.id
    )
@login_required
def share_file(request, file_id):
    file = get_object_or_404(File, id=file_id, owner=request.user)

    if request.method == "POST":
        email = request.POST.get("email")
        print(f"Entered Email: '{email}'")
        permission = request.POST.get("permission")
        expires = request.POST.get("expires_at")
        try:
            receiver = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "User Not Found.")
            return redirect("myfiles")

        password=generate_random_password()
        with transaction.atomic():

            shared = SharedFile.objects.create(
                file=file,
                shared_by=request.user,
                shared_with=receiver,
                receiver_email=receiver.email,
                permission=permission,
                share_password=make_password(password),
                expires_at=parse_datetime(expires) if expires else None,
            )

            sender = (
            request.user.get_full_name()
            or request.user.first_name
            or request.user.email
            )

            Notification.objects.create(
            user=receiver,
            title="New File Shared",
            message=f"{sender} shared '{file.file_name}' with you.",
            )
            link = request.build_absolute_uri(
            reverse("download_shared_file", args=[shared.share_token])
            )
            send_email_async(
                subject="VaultShare - File Shared",
                message=f"""
Hello {receiver.full_name},

{request.user.full_name} has shared a file with you.

File Name: {file.file_name}
One-Time Password:{password}

Please log in to VaultShare to access it.

Regards,
VaultShare Team
""",
                recipient=receiver.email,
            )

            create_audit_log(user=request.user, action="Shared File",description=f"Shared File: {shared.file.file_name}",request=request)
            messages.success(request, "File Shared Successfully.")

    return redirect("myfiles")

def generate_share_link(request, file_id):
    file = get_object_or_404(File, id=file_id, owner=request.user)

    if request.method == "POST":
        password = request.POST.get("password")
        expiry_minutes = int(request.POST.get("expiry", 60))
        expires = timezone.now() + timedelta(minutes=expiry_minutes)

        try:
            share = SecureShareLink.objects.create(
                file=file,
                created_by=request.user,
                password=make_password(password),
                expires_at=expires,
            )

            print("Share Created!")
            print("ID:", share.id)
            print("Token:", share.token)

            link = request.build_absolute_uri(
                reverse("download_public_file", args=[share.token])
            )

            print("Generated Link:", link)

            messages.success(request, f"Share Link: {link}")
            create_audit_log(user=request.user, action="generate_share_link",description=f"Share Link Generated: {file.file_name}",request=request)

        except Exception as e:
            print("ERROR:", e)
            messages.error(request, str(e))

    return redirect("myfiles")


def download_public_file(request, token):
    share = get_object_or_404(
        SecureShareLink,
        token=token,
        is_active=True
    )

    if request.method != "POST":
        return render(
            request,
            "files/shared_password.html",
            {"token": token}
        )

    if share.expires_at and timezone.now() > share.expires_at:
        share.is_active = False
        share.save(update_fields=["is_active"])

        messages.error(
            request,
            "This link has expired."
        )
        return redirect("home")

    password = request.POST.get("password")

    if not check_password(password, share.password):
        messages.error(
            request,
            "Incorrect password."
        )
        return redirect(
            "download_shared_file",
            token=token
        )

    file = share.file
    encrypted_path = file.file.path

    if not os.path.exists(encrypted_path):
        messages.error(
            request,
            "The encrypted file could not be found."
        )
        return redirect("home")

    temp_dir = os.path.join(
        settings.MEDIA_ROOT,
        "temp_download"
    )
    os.makedirs(temp_dir, exist_ok=True)

    decrypted_path = os.path.join(
        temp_dir,
        file.file_name
    )

    try:

        if file.encryption_type == "AES256":

            aes_key = bytes(
                file.encrypted_key
            )

        elif file.encryption_type == "Dual":

            private_key = load_private_key(
                file.owner.id
            )

            aes_key = decrypt_aes_key(
                private_key,
                bytes(file.encrypted_key)
            )

        else:
            messages.error(
                request,
                "Unsupported encryption type."
            )
            return redirect("home")

        nonce = bytes(file.nonce)

        if len(aes_key) != 32 or len(nonce) != 12:
            raise ValueError(
                "Invalid encryption metadata."
            )

        # AES-GCM authentication
        decrypt_file(
            encrypted_path,
            decrypted_path,
            aes_key,
            nonce
        )

        # SHA-256 integrity verification
        calculated_hash = generate_sha256(
            decrypted_path
        )

        if (
            file.sha256_hash
            and calculated_hash.lower()
            != file.sha256_hash.lower()
        ):

            create_audit_log(
                user=(
                    request.user
                    if request.user.is_authenticated
                    else None
                ),
                action="FILE_INTEGRITY_FAILED",
                description=(
                    f"Shared file integrity verification "
                    f"failed for '{file.file_name}'."
                ),
                request=request,
            )

            messages.error(
                request,
                "Download blocked. File integrity verification failed."
            )

            return redirect("home")

        return FileResponse(
            open(decrypted_path, "rb"),
            as_attachment=True,
            filename=file.file_name
        )

    except InvalidTag:

        if os.path.exists(decrypted_path):
            os.remove(decrypted_path)

        messages.error(
            request,
            "Download blocked. The file is corrupted or has been modified."
        )

        return redirect("home")

    except Exception:

        if os.path.exists(decrypted_path):
            os.remove(decrypted_path)

        messages.error(
            request,
            "Unable to securely decrypt this file."
        )

        return redirect("home")

def download_shared_file(request, token):
    share = get_object_or_404(SharedFile, share_token=token)

    if not share.is_active:
        messages.error(request, "This share link has been revoked.")
        return redirect("received_files" if request.user.is_authenticated else "home")

    if share.expires_at and timezone.now() >= share.expires_at:
        share.is_active = False
        share.save()
        messages.error(request, "This share link has expired.")
        return redirect("received_files" if request.user.is_authenticated else "home")

    if share.current_downloads >= share.max_downloads:
        messages.error(request, "Download limit reached for this shared file.")
        return redirect("received_files" if request.user.is_authenticated else "home")

    if not request.user.is_authenticated:
        messages.error(request, "Please login first.")
        return redirect("login")

    if share.shared_with != request.user:
        messages.error(request, "You are not authorized to access this file.")
        return redirect("received_files")

    if request.method == "GET":
        return render(
            request,
            "files/shared_password.html",
            {"token": token, "type": "shared"},
        )

    password = request.POST.get("password")
    if not check_password(password, share.share_password):
        messages.error(request, "Incorrect password.")
        return redirect("download_shared_file", token=token)

    file = share.file
    encrypted_path = file.file.path
    temp_dir = os.path.join(settings.MEDIA_ROOT, "temp_download")
    os.makedirs(temp_dir, exist_ok=True)
    decrypted_path = os.path.join(temp_dir, file.file_name)

    if file.encryption_type == "AES256":
        aes_key = bytes(file.encrypted_key)
    elif file.encryption_type == "Dual":
        private_key = load_private_key(file.owner.id)
        aes_key = decrypt_aes_key(private_key, bytes(file.encrypted_key))
    else:
        messages.error(request, "Unsupported encryption type.")
        return redirect("received_files")

    try:
        decrypt_file(
            encrypted_path,
            decrypted_path,
            aes_key,
            bytes(file.nonce) if file.nonce else None,
        )

        current_hash = generate_sha256(decrypted_path)

        if file.sha256_hash and current_hash.lower() != file.sha256_hash.lower():
            if os.path.exists(decrypted_path):
                os.remove(decrypted_path)

            create_audit_log(
                user=request.user,
                action="FILE_INTEGRITY_FAILED",
                description=(
                    f"Shared file SHA-256 verification failed "
                    f"for '{file.file_name}'."
                ),
                request=request,
            )
            messages.error(
                request,
                "Integrity verification failed! The file may have been tampered with.",
            )
            return redirect("received_files")

        share.current_downloads += 1
        share.save(update_fields=["current_downloads"])

        create_audit_log(
            user=request.user,
            action="FILE_DOWNLOAD",
            description=(
                f"Shared file '{file.file_name}' downloaded successfully "
                f"after integrity verification."
            ),
            request=request,
        )

        return FileResponse(
            open(decrypted_path, "rb"),
            as_attachment=True,
            filename=file.file_name,
        )

    except InvalidTag:
        if os.path.exists(decrypted_path):
            os.remove(decrypted_path)

        create_audit_log(
            user=request.user,
            action="FILE_INTEGRITY_FAILED",
            description=(
                f"AES-GCM authentication failed for shared file "
                f"'{file.file_name}'. Possible corruption or tampering."
            ),
            request=request,
        )
        messages.error(
            request,
            "Download blocked. The file is corrupted or has been modified.",
        )
        return redirect("received_files")

    except Exception:
        if os.path.exists(decrypted_path):
            os.remove(decrypted_path)

        create_audit_log(
            user=request.user,
            action="FILE_DOWNLOAD_FAILED",
            description=(
                f"Secure shared download failed for '{file.file_name}'."
            ),
            request=request,
        )
        messages.error(request, "Download failed. Please try again.")
        return redirect("received_files")

def received_file(request):
    received = list(
        SharedFile.objects.filter(
            shared_with=request.user
        ).select_related(
            "file",
            "shared_by"
        )
    )

    requested_share_ids = set(
        AccessRequest.objects.filter(
            shared_file__in=received,
            requested_by=request.user
        ).values_list(
            "shared_file_id",
            flat=True
        )
    )

    for share in received:
        share.already_requested = share.id in requested_share_ids

    return render(
        request,
        "files/received_files.html",
        {
            "received": received,
            "now": timezone.now(),
        },
    )

def notification(request):
    notification = Notification.objects.filter(user=request.user).order_by(
        "-created_at"
    )

    return render(request, "files/notification.html", {"notification": notification})


def shared_history(request):
    shared_files = (
        SharedFile.objects.filter(shared_by=request.user)
        .select_related("file", "shared_with")
        .order_by("-shared_at")
    )
    now = timezone.now()
    for share in shared_files:
        if not share.is_active:
            share.status = "Revoked"

        elif share.expires_at and share.expires_at <= now:
            share.status = "Expired"

        elif share.current_downloads >= share.max_downloads:
            share.status = "Download Limit Reached"

        else:
            share.status = "Active"

    return render(
        request,
        "files/shared_history.html",
        {
            "shared_files": shared_files,
            "now": timezone.now(),
        },
    )


def delete_all_notification(request):
    if request.method == "POST":
        Notification.objects.filter(user=request.user).delete()
        messages.success(request, "All notifications are deleted.")
    return redirect("notification")


def get_share_status(share):
    if not share.is_active:
        return "Revoked"
    if share.expires_at and timezone.now() >= share.expires_at:
        return "Expired"

    if share.current_downloads >= share.max_downloads:
        return "Download Limit Reached"

    return "Active"


def revoke_share(request, share_id):
    if request.method != "POST":
        return redirect("shared_history")

    share = get_object_or_404(SharedFile, id=share_id, shared_by=request.user)
    if share.current_downloads > 0:
        messages.warning(
            request, "This file has already been downloaded and cannot be revoked."
        )
        return redirect("shared_history")
    if share.expires_at and timezone.now() >= share.expires_at:
        messages.warning(request, "This share has already expired.")
        return redirect("shared_history")

    if not share.is_active:
        messages.info(request, "This share has already been revoked.")
        return redirect("shared_history")
    share.is_active = False
    share.save()

    messages.success(
        request, f"Access to '{share.file.file_name}' has been revoked successfully."
    )
    create_audit_log(
    user=request.user,
    action="SHARE_LINK_REVOKED",
    description=f"Revoked secure share link for: {share.file.file_name}",
    request=request
)
    return redirect("shared_history")


def request_access_again(request, token):
    shared = get_object_or_404(SharedFile, share_token=token)

    if request.user == shared.shared_by:
        messages.error(request, "You cannot request your own file.")
        return redirect("user_dashboard")
    already_requested = AccessRequest.objects.filter(
        shared_file=shared, requested_by=request.user
    ).exists()

    if already_requested:
        messages.warning(request, "You have already requested access for this file.")
        return redirect("received_files")

    AccessRequest.objects.create(shared_file=shared, requested_by=request.user)

    Notification.objects.create(
        user=shared.shared_by,
        title="Access Request",
       message=f"{request.user.full_name or request.user.email} requested access again for '{shared.file.file_name}'."
    )

    messages.success(request, "Your access request has been sent to the sender.")
    return redirect("received_files")
def access_requests(request):

    requests = AccessRequest.objects.filter(
        shared_file__shared_by=request.user,
        status="Pending"
    ).select_related(
        "requested_by",
        "shared_file",
        "shared_file__file",
    )

    return render(
        request,
        "files/access_requests.html",
        {"requests": requests},
    )


@login_required
def approve_request(request, request_id):

    access = get_object_or_404(
        AccessRequest,
        id=request_id,
        status="Pending"
    )

    if access.shared_file.shared_by != request.user:
        messages.error(request, "Unauthorized")
        return redirect("access_requests")

    shared = access.shared_file

    shared.is_active = True
    shared.current_downloads = 0
    shared.max_downloads = 1
    shared.expires_at = timezone.now() + timedelta(days=2)

    # Generate a new secure link
    shared.share_token = uuid.uuid4()
    new_password=generate_random_password()
    shared.share_password=make_password(new_password)
    shared.save()
    link=request.build_absolute_uri(reverse("download_shared_file", args=[shared.share_token]))
    access.status = "Approved"
    access.save()

    Notification.objects.create(
        user=access.requested_by,
        title="Access Approved",
        message=f"Your request for '{shared.file.file_name}' has been approved. You can download the file once."
    )
    send_email_async(
        subject="VaultShare - Access Approved",
        message=f"""
Hello {access.requested_by.full_name},

Your request to access the file has been approved.

File Name:
{shared.file.file_name}

New Download Link:
{link}

New One-Time Password:
{new_password}

This password replaces the previous one.

You can download this file only once before the link expires.""",
        recipient=access.requested_by.email,
    )

    messages.success(request, "Access approved.")

    return redirect("access_requests")


@login_required
def reject_request(request, request_id):

    access = get_object_or_404(
        AccessRequest,
        id=request_id,
        status="Pending"
    )

    if access.shared_file.shared_by != request.user:
        messages.error(request, "Unauthorized")
        return redirect("access_requests")

    access.status = "Rejected"
    access.save()

    Notification.objects.create(
        user=access.requested_by,
        title="Access Rejected",
        message=f"Your request for '{access.shared_file.file.file_name}' has been rejected."
    )

    messages.success(request, "Request rejected.")

    return redirect("access_requests")


@login_required
def verify_file_integrity(request, file_id):
    """
    Cryptographic SHA-256 integrity verification endpoint.
    Decrypts the file payload temporarily in memory to verify SHA-256 checksum authenticity.
    """
    file = None
    try:
        file = File.objects.get(id=file_id, owner=request.user)
    except File.DoesNotExist:
        shared = SharedFile.objects.filter(file_id=file_id, shared_with=request.user).first()
        if shared:
            file = shared.file

    if not file:
        messages.error(request, "File not found or access denied.")
        return redirect("myfiles")

    encrypted_path = file.file.path
    if not os.path.exists(encrypted_path):
        messages.error(request, f"File payload for '{file.file_name}' does not exist on disk.")
        return redirect(request.META.get("HTTP_REFERER", "myfiles"))

    temp_dir = os.path.join(settings.MEDIA_ROOT, "temp_integrity")
    os.makedirs(temp_dir, exist_ok=True)
    temp_decrypted = os.path.join(temp_dir, f"verify_{uuid.uuid4().hex}_{file.file_name}")

    try:
        if file.encryption_type == "AES256":
            aes_key = bytes(file.encrypted_key)
        else:
            private_key = load_private_key(file.owner.id)
            aes_key = decrypt_aes_key(private_key, bytes(file.encrypted_key))

        decrypt_file(encrypted_path, temp_decrypted, aes_key, bytes(file.nonce) if file.nonce else None)
        calculated_hash = generate_sha256(temp_decrypted)
    except Exception as e:
        messages.error(request, f"Decryption failed during integrity check: {str(e)}")
        return redirect(request.META.get("HTTP_REFERER", "myfiles"))
    finally:
        if os.path.exists(temp_decrypted):
            try:
                os.remove(temp_decrypted)
            except Exception:
                pass

    if not file.sha256_hash:
        file.sha256_hash = calculated_hash
        file.save(update_fields=["sha256_hash"])

    is_valid = (calculated_hash.lower() == file.sha256_hash.lower())

    if is_valid:
        create_audit_log(
            user=request.user,
            action="FILE_INTEGRITY_VERIFIED",
            description=f"Verified Integrity for '{file.file_name}': SHA-256 Match ({calculated_hash[:16]}...)",
            request=request,
        )
        if request.headers.get("x-requested-with") == "XMLHttpRequest" or request.GET.get("format") == "json":
            return JsonResponse({
                "status": "success",
                "match": True,
                "file_name": file.file_name,
                "expected_hash": file.sha256_hash,
                "calculated_hash": calculated_hash,
                "message": f"Cryptographic Integrity Verified! SHA-256 checksum matched for '{file.file_name}'."
            })
        messages.success(
            request,
            f"✓ SHA-256 Integrity Verified for '{file.file_name}': Checksum ({calculated_hash[:16]}...) matches - File is authentic & untampered."
        )
    else:
        create_audit_log(
            user=request.user,
            action="FILE_INTEGRITY_FAILED",
            description=f"CRITICAL: Integrity Check Failed for '{file.file_name}' (Hash Mismatch!)",
            request=request,
        )
        if request.headers.get("x-requested-with") == "XMLHttpRequest" or request.GET.get("format") == "json":
            return JsonResponse({
                "status": "error",
                "match": False,
                "file_name": file.file_name,
                "expected_hash": file.sha256_hash,
                "calculated_hash": calculated_hash,
                "message": f"CRITICAL INTEGRITY FAILURE! SHA-256 hash mismatch detected for '{file.file_name}'."
            }, status=400)
        messages.error(
            request,
            f"⚠ CRITICAL INTEGRITY WARNING: SHA-256 checksum mismatch for '{file.file_name}'. The file may have been modified or corrupted!"
        )

    return redirect(request.META.get("HTTP_REFERER", "myfiles"))
