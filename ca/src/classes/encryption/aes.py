import os, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Ajoute le chemin du répertoire parent au chemin de recherche des modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class ChiffrementAES:
    def __init__(self):
        """
            Initialise la classe ChiffrementAES avec une clé AES de 256 bits.
            Les clés AES des autres entités seront stocké dans un dictionnaire.
        """
        self.key = self.generate_key()
        self.aes_keys = {}

    def generate_key(self):
        """
            Génère une clé AES de 256 bits et la retourne.

            Returns:
                bytes: La clé AES de 256 bits.
        """
        return os.urandom(32)

    def insert_aes(self, aes_key, identifier):
        """
        Insère une clé AES associée à un identifiant dans le dictionnaire.

        Args:
            aes_key (bytes): La clé AES à insérer.
            identifier (str): L'identifiant associé à la clé.
        """
        self.aes_keys[identifier] = aes_key

    def get_aes_key(self, identifier):
        """
            Récupère la clé AES associée à un identifiant dans le dictionnaire.

            Args:
                identifier (str): L'identifiant de la clé à récupérer.

            Returns:
                bytes: La clé AES associée à l'identifiant.
        """
        return self.aes_keys.get(identifier)
    
    def get_my_aes_key(self):
        """
            Retourne la clé AES du client.
        """
        return self.key
    
    def get_serialized_key(self):
        """
        Retourne la clé AES du client en format hexadécimal.

        Returns:
            str: La clé AES du client en format hexadécimal.
        """
        try:
            serialized_key = self.key.hex()
            return serialized_key
        except Exception as e:
            print(f"Erreur lors de la sérialisation de la clé AES : {e}")
            return None

    def receive_aes_key(self, aes_key_hex):
        """
            Reçoit une clé AES au format hexadécimal et la convertit en bytes.

            Args:
                aes_key_hex (str): La clé AES au format hexadécimal.

            Returns:
                bytes: La clé AES convertie en bytes.
        """
        try:
            aes_key = bytes.fromhex(aes_key_hex)
            return aes_key
        except Exception as e:
            print(f"Erreur lors de la conversion de la clé AES : {e}")
            return None
            
    def pad_data(self, data):
        """
            Ajoute un padding PKCS#7 aux données pour qu'elles correspondent à la taille du bloc AES.

            Args:
                data (bytes): Les données à padder.

            Returns:
                bytes: Les données paddées.
        """
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

    def unpad_data(self, data):
        """
            Supprime le padding PKCS#7 des données décryptées.

            Args:
                data (bytes): Les données paddées.

            Returns:
                bytes: Les données dé-paddées.
        """
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        return unpadded_data

    def encrypt(self, data):
        """
            Chiffre les données avec AES-256 en mode CBC avec padding PKCS#7.

            Args:
                data (bytes): Les données à chiffrer.

            Returns:
                bytes: Les données chiffrées, incluant l'IV au début.
        """
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = self.pad_data(data)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, data):
        """
            Déchiffre les données avec AES-256 en mode CBC, puis supprime le padding PKCS#7.

            Args:
                data (bytes): Les données chiffrées, incluant l'IV au début.

            Returns:
                bytes: Les données déchiffrées.
        """
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self.unpad_data(padded_plaintext)
        return plaintext

"""
Exemple d'utilisation :       
"""

# cipher = ChiffrementAES()

# data = b"Ceci est un message secret."
# encrypted_data = cipher.encrypt(data)
# decrypted_data = cipher.decrypt(encrypted_data)

# print(f"Original data: {data}")
# print(f"Encrypted data: {encrypted_data}")
# print(f"Decrypted data: {decrypted_data}")
