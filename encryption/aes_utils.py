import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_aes_key():
    """
    Generate a random 256-bit AES key.
    """
    return AESGCM.generate_key(bit_length=256)


def encrypt_file(input_path, output_path):
    """
    Encrypt a file using AES-256-GCM.

    Returns:
        aes_key (bytes)
        nonce (bytes)
    """

    # Generate AES-256 key
    aes_key = generate_aes_key()

    # AES-GCM requires a 12-byte nonce
    nonce = os.urandom(12)

    # Read original file
    with open(input_path, "rb") as file:
        plaintext = file.read()

    # Create AES cipher
    aesgcm = AESGCM(aes_key)

    # Encrypt
    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        None
    )

    # Save encrypted file
    with open(output_path, "wb") as file:
        file.write(ciphertext)

    return aes_key, nonce


def decrypt_file(input_path, output_path, aes_key, nonce):
    """
    Decrypt an AES-256-GCM encrypted file.
    """
    if isinstance(aes_key, memoryview):
        aes_key = bytes(aes_key)
    if isinstance(nonce, memoryview):
        nonce = bytes(nonce)

    with open(input_path, "rb") as file:
        ciphertext = file.read()

    aesgcm = AESGCM(aes_key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    with open(output_path, "wb") as file:
        file.write(plaintext)