import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

class ChiffrementAES:

    def __init__(self, key_file="aes_key.bin", force=False):
        self.key_file = key_file
        self.force = force

        # Check if key file exists, generate a new one if missing or force=True
        if not os.path.exists(self.key_file) or self.force:
            self.generate_key()

        # Try to read the key, raise an exception if there's an error
        try:
            with open(self.key_file, "rb") as f:
                self.key = f.read()
        except FileNotFoundError:
            raise FileNotFoundError("Error: Key file not found.") from None

    def generate_key(self):
        """
            Generates a 256-bit AES key and saves it to the key file.
        """
        self.key = os.urandom(32)
        with open(self.key_file, "wb") as f:
            f.write(self.key)

    def pad_data(self, data):
        """
            Pads data with PKCS#7 padding scheme to match AES block size.
        """
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

    def unpad_data(self, data):
        """
            Removes PKCS#7 padding from decrypted data.
        """
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        return unpadded_data

    def encrypt(self, data):
        """
            Encrypts data with AES-256 in CBC mode with PKCS#7 padding.
        """
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = self.pad_data(data)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, data):
        """
            Decrypts data with AES-256 in CBC mode, removes PKCS#7 padding.
        """
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self.unpad_data(padded_plaintext)
        return plaintext

# Example usage
cipher = ChiffrementAES()

data = b"Ceci est un message secret."
encrypted_data = cipher.encrypt(data)
decrypted_data = cipher.decrypt(encrypted_data)

print(f"Original data: {data}")
print(f"Encrypted data: {encrypted_data}")
print(f"Decrypted data: {decrypted_data}")
