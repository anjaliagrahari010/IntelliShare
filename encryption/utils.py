import os
from cryptography.fernet import Fernet
import secrets
import string
def generate_key():
    """
    Generate a new encryption key.
    """
    return Fernet.generate_key()


def encrypt_file(input_path, output_path):
    """
    Encrypt a file and save it to output_path.
    """

    key = generate_key()

    cipher = Fernet(key)

    with open(input_path, "rb") as file:
        data = file.read()

    encrypted_data = cipher.encrypt(data)

    with open(output_path, "wb") as file:
        file.write(encrypted_data)

    return key

def decrypt_file(encrypted_path,output_path,key):
    if isinstance(key, str):
        key = key.encode()


    cipher=Fernet(key)
    with open(encrypted_path,"rb") as f:
        encrypted_data=f.read()
    decrypted_data=cipher.decrypt(encrypted_data)
    with open(output_path,"wb") as f:
        f.write(decrypted_data)
