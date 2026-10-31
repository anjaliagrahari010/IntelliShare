import os
from django.conf import settings
from cryptography.hazmat.primitives import serialization

def save_keys(user_id, private_key, public_key):
    """
    Save RSA keys to media/keys/
    """

    key_dir = os.path.join(settings.MEDIA_ROOT, "keys")

    os.makedirs(key_dir, exist_ok=True)

    private_path = os.path.join(key_dir, f"{user_id}_private.pem")
    public_path = os.path.join(key_dir, f"{user_id}_public.pem")

    with open(private_path, "wb") as f:
        f.write(private_key)

    with open(public_path, "wb") as f:
        f.write(public_key)

    return private_path, public_path


def load_private_key(user_id):

    path = os.path.join(settings.MEDIA_ROOT, "keys", f"{user_id}_private.pem")

    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


def load_public_key(user_id):

    path = os.path.join(settings.MEDIA_ROOT, "keys", f"{user_id}_public.pem")

    with open(path, "rb") as f:
        return serialization.load_pem_public_key(
            f.read()
        )