from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization,hashes


def generate_rsa_key_pair():
    """
    Generate a 2048-bit RSA key pair.

    Returns:
        tuple(bytes, bytes): (private_key_pem, public_key_pem)
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

def encrypt_aes_key(public_key, aes_key):
    """
    Encrypt the AES key using the recipient's RSA public key.
    """
    if isinstance(aes_key, memoryview):
        aes_key = bytes(aes_key)

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key

def decrypt_aes_key(private_key, encrypted_aes_key):
    """
    Decrypt the AES key using the owner's RSA private key.
    """
    if isinstance(encrypted_aes_key, memoryview):
        encrypted_aes_key = bytes(encrypted_aes_key)

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key