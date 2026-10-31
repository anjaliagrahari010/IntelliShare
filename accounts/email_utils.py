from threading import Thread
from django.core.mail import send_mail
from django.conf import settings


def send_email_async(subject, message, recipient):
    """
    Send email in a background thread.
    """

    def _send():
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[recipient],
            fail_silently=False,
        )

    Thread(target=_send, daemon=True).start()