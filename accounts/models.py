import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone
from .managers import CustomUserManager
from datetime import timedelta
import hashlib


class User(AbstractUser):

    username = None
    full_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, blank=True)
    profile_picture = models.ImageField(
        upload_to='profiles/',
        blank=True,
        null=True
    )
    two_factor_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email
class Folder(models.Model):
        owner = models.ForeignKey(
            settings.AUTH_USER_MODEL,
            on_delete=models.CASCADE,
            related_name='folders'
        )
        name = models.CharField(max_length=255)
        parent = models.ForeignKey(
            'self',
            on_delete=models.CASCADE,
            null=True, blank=True,
            related_name='subfolders'
        )
        created_at = models.DateTimeField(auto_now_add=True)

        def __str__(self):
            return self.name


class File(models.Model):

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='files'
    )

    folder = models.ForeignKey(
        Folder,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='files'
    )

    file_name = models.CharField(max_length=255)

    file = models.FileField(
    upload_to='encrypted_files/',
    max_length=500
)

    file_size = models.BigIntegerField(default=0)

    # RSA encrypted AES key
    encrypted_key = models.BinaryField()

    # AES-GCM nonce


    is_encrypted = models.BooleanField(default=True)

    uploaded_at = models.DateTimeField(auto_now_add=True)

    sha256_hash = models.CharField(max_length=64, blank=True, default="")

    ENCRYPTION_CHOICES = (
        ('AES256', 'AES-256'),
        ('Dual', 'Dual Layer(AES + RSA)'),
    )
    nonce = models.BinaryField(null=True, blank=True)
    encryption_type = models.CharField(
        max_length=20,
        choices=ENCRYPTION_CHOICES,
        default='AES256'
    )

    def __str__(self):
        return self.file_name

class SharedFile(models.Model):
        PERMISSION_CHOICES = [
            ('view', 'View'),
            ('download', 'Download'),
        ]

        file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='shares')
        shared_by = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE,related_name='shared_files_sent')
        shared_with = models.ForeignKey(settings.AUTH_USER_MODEL,
            on_delete=models.CASCADE,
            null=True, blank=True,       # null = public link share
            related_name='shared_files_received'
        )
        receiver_email = models.EmailField(null=True,blank=True)
        permission = models.CharField(max_length=20, choices=PERMISSION_CHOICES, default='view')
        share_token = models.UUIDField(default=uuid.uuid4, unique=True)   # for shareable link
        share_password = models.CharField(max_length=255, blank=True, null=True)  # store hashed
        expires_at = models.DateTimeField(null=True, blank=True)
        shared_at = models.DateTimeField(auto_now_add=True)
        max_downloads = models.PositiveIntegerField(default=1)
        current_downloads = models.PositiveIntegerField(default=0)
        is_active = models.BooleanField(default=True)

class Notification(models.Model):

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notification"
    )

    title = models.CharField(max_length=200)

    message = models.TextField()

    is_read = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class EmailVerificationToken(models.Model):
        user=models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='verification_tokens')
        tokens=models.UUIDField(default=uuid.uuid4,unique=True)
        expires_at=models.DateTimeField()
        is_used=models.BooleanField(default=False)
        created_at=models.DateTimeField(auto_now_add=True)
        def is_expired(self):
            return timezone.now() > self.expires_at
        def __str__(self):
            return f"Verification token for {self.user.email}"


class EncryptedFile(models.Model):
    ENCRYPTION_CHOICES = [
        ("AES", "AES-256"),
        ("Dual", "Dual Layer Encryption"),
    ]
    owner=models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    original_fileName=models.CharField(max_length=255)
    encrypted_file=models.FileField(upload_to='encrypted_files/')
    encryption_key=models.BinaryField()
    encrypted_key = models.BinaryField(null=True,blank=True)
    share_token=models.UUIDField(default=uuid.uuid4, unique=True,editable=False)
    expires_at=models.DateTimeField()
    created_at=models.DateTimeField(auto_now_add=True)
    is_active=models.BooleanField(default=True)

    def __str__(self):
        return self.original_fileName


class SecureShareLink(models.Model):
    file=models.ForeignKey(File,on_delete=models.CASCADE, related_name="share_links")
    token=models.UUIDField(default=uuid.uuid4,unique=True,editable=False)
    created_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)
    password=models.CharField(max_length=255,null=True,blank=True)
    expires_at=models.DateTimeField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    is_active=models.BooleanField(default=True)

    def __self__(self):
        return str(self.token)

class Downloading(models.Model):
    share = models.ForeignKey(
        SecureShareLink,
        on_delete=models.CASCADE
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    ip_address = models.GenericIPAddressField()

    downloaded_at = models.DateTimeField(auto_now_add=True)

class LoginOTP(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="login_otps"
    )

    otp = models.CharField(max_length=6)

    expires_at = models.DateTimeField()

    is_verified = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=5)
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        return f"OTP for {self.user.email}"

class AccessRequest(models.Model):
    STATUS_CHOICE=[("Pending","Pending"),("Approved","Approved")]
    shared_file=models.ForeignKey("SharedFile",on_delete=models.CASCADE, related_name="access_requests")
    requested_by=models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    status=models.CharField(max_length=20,choices=STATUS_CHOICE,default="Pending",db_index=True)
    requested_at=models.DateTimeField(default=timezone.now)
    class Meta:
        unique_together=("shared_file","requested_by")
    def __str__(self):
        return f"{self.requested_by}-{self.shared_file.file.file_name}"



class AuditLog(models.Model):

    ACTION_CHOICES = [

    ("LOGIN", "Login"),
    ("LOGIN_FAILED", "Login Failed"),
    ("LOGOUT", "Logout"),

    ("OTP_VERIFIED", "OTP Verified"),
    ("OTP_FAILED", "OTP Failed"),

    ("FILE_UPLOAD", "File Upload"),
    ("FILE_DOWNLOAD", "File Download"),
    ("FILE_DELETE", "File Delete"),

    ("FILE_SHARE", "File Share"),

    ("SHARE_LINK_CREATED", "Share Link Created"),
    ("SHARE_LINK_REVOKED", "Share Link Revoked"),

    (
        "SHARE_PASSWORD_FAILED",
        "Share Password Failed"
    ),

    (
        "EXPIRED_LINK_ACCESS",
        "Expired Link Access"
    ),

    (
        "REVOKED_LINK_ACCESS",
        "Revoked Link Access"
    ),

    ("ACCESS_REQUEST", "Access Request"),
    ("ACCESS_APPROVED", "Access Approved"),
    ("ACCESS_DENIED", "Access Denied"),

    (
        "MALWARE_DETECTED",
        "Malware Detected"
    ),

    (
        "INTEGRITY_FAILURE",
        "Integrity Verification Failure"
    ),

    ("PASSWORD_CHANGE", "Password Change"),

    ("2FA_ENABLED", "2FA Enabled"),
    ("2FA_DISABLED", "2FA Disabled"),
]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs"
    )

    action = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES
    )

    reason = models.TextField(
        blank=True,
        default=""
    )

    description = models.TextField()

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True
    )

    user_agent = models.TextField(
        blank=True,
        null=True
    )

    metadata = models.JSONField(
        default=dict,
        blank=True
    )

    risk_level = models.CharField(
        max_length=20,
        default="LOW"
    )

    risk_score = models.SmallIntegerField(
        default=0
    )

    success = models.BooleanField(
        default=True
    )

    suspicious = models.BooleanField(
        default=False
    )

    device_information = models.JSONField(
        default=dict,
        blank=True
    )

    event_type = models.CharField(
        max_length=50,
        default="AUTHENTICATION"
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user} - {self.action} - {self.created_at}"
