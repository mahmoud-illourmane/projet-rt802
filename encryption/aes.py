import os, sys, base64
from typing import Union  # Retour de fonction [str|int]

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Ajoute le chemin du répertoire parent au chemin de recherche des modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class ChiffrementAES:
    def __init__(self):
        """
            Initialise une nouvelle instance de la classe ChiffrementAES.

            Cette classe utilise une clé AES de 256 bits par défaut. Les clés AES des autres entités sont stockées dans un dictionnaire de clés.

            Attributes:
                key (bytes): La clé AES utilisée pour le chiffrement et le déchiffrement.
                aes_keys (dict): Un dictionnaire pour stocker les clés AES associées à des identifiants.
        """
        self.key = self.generate_key()
        self.aes_keys = {}

    def generate_key(self):
        """
            Génère une clé AES de 256 bits aléatoire et la retourne.

            Returns:
                bytes: La clé AES de 256 bits générée aléatoirement.
        """
        return os.urandom(32)

    def insert_aes_key(self, aes_key: bytes, identifiant: str):
        """
            Insère une clé AES associée à un identifiant dans le dictionnaire des clés.

            Args:
                aes_key (bytes): La clé AES à insérer.
                identifiant (str): L'identifiant associé à la clé.
        """
        self.aes_keys[identifiant] = aes_key

    def get_aes_key(self, identifiant: str) -> Union[bytes, None]:
        """
            Récupère la clé AES associée à un identifiant dans le dictionnaire.

            Args:
                identifiant (str): L'identifiant de la clé à récupérer.

            Returns:
                bytes: La clé AES associée à l'identifiant.
                ou
                None: Si pas de correspondance.
        """
        return self.aes_keys.get(identifiant)
    
    def get_my_aes_key(self) -> bytes:
        """
            Retourne la clé AES de l'instance.
        """
        return self.key
    
    def get_my_aes_key_serialized(self) -> Union[str, None]:
        """
            Retourne la clé AES en format hexadécimal.

            Returns:
                str: La clé AES en format hexadécimal.
                ou
                None: En cas d'erreur.
        """
        try:
            serialized_key = self.key.hex()
            return serialized_key
        except TypeError as te:
            print(f"Erreur lors de la sérialisation en hexadécimal de la clé AES :\n{te}")
            return None

    def get_serialized_key(self, aes_key: bytes) -> Union[str, None]:
        """
            Retourne une clé AES au format hexadécimal.

            Returns:
                str: La clé AES à transformer en format hexadécimal.
                ou
                None: En cas d'erreur.
        """
        try:
            serialized_key = aes_key.hex()
            return serialized_key
        except TypeError as te:
            print(f"Erreur lors de la sérialisation en hexadécimal de la clé AES (get_serialized_key) :\n{te}")
            return None

    def convert_aes_key_from_hex_to_bytes(self, aes_key_hex) -> Union[bytes, None]:
        """
            Reçoit une clé AES au format hexadécimal et la convertit en bytes.

            Args:
                aes_key_hex (str): La clé AES au format hexadécimal.

            Returns:
                bytes: La clé AES convertie en bytes.
                ou
                None: En cas d'erreur.
        """
        try:
            aes_key = bytes.fromhex(aes_key_hex)
            return aes_key
        except ValueError as ve:
            print(f"Erreur lors de la conversion de la clé AES :\n{ve}")
            return None
            
    def pad_data(self, data: bytes) -> bytes:
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

    def unpad_data(self, data: bytes) -> bytes:
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

    def encrypt(self, data: bytes, key=None, use_base64=False) -> Union[bytes, str, None]:
        """
            Chiffre les données avec AES-256 en mode CBC avec padding PKCS#7.

            Args:
                data (bytes): Les données à chiffrer.
                key (bytes, facultatif): La clé AES à utiliser pour le chiffrement. Si None, utilise la clé de l'instance.
                use_base64 (bool, facultatif): Indique si les données chiffrées doivent être converties en base64. Par défaut, False.

            Returns:
                bytes: Les données chiffrées, incluant l'IV au début. 
                ou
                str: Converties en base64 si use_base64=True 
                ou 
                None: En cas d'erreur.
        """
        try:
            if key is None:
                key = self.key
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padded_data = self.pad_data(data)
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_data = iv + ciphertext
            if use_base64:
                return base64.b64encode(encrypted_data)
            else:
                return encrypted_data
            
        except ValueError as ve:
            print(f"Erreur de valeur lors du chiffrement :\n{ve}")
            return None
        except Exception as e:
            print(f"Erreur lors du chiffrement :\n{e}")
            return None
        
    def decrypt(self, data, key=None, use_base64=False):
        """
            Déchiffre les données avec AES-256 en mode CBC, puis supprime le padding PKCS#7.

            Args:
                data (bytes or str): Les données chiffrées, incluant l'IV au début. Si use_base64 est True, 
                data doit être une chaîne de caractères (string) encodée en base64.
                key (bytes, facultatif): La clé AES à utiliser pour le déchiffrement. Si None, utilise la clé de l'instance.
                use_base64 (bool, facultatif): Indique si les données chiffrées sont encodées en base64. Par défaut, False.

            Returns:
                bytes: Les données déchiffrées.
        """
        try:
            if key is None:
                key = self.key
                
            if use_base64:
                data = base64.b64decode(data)
                
            iv = data[:16]
            ciphertext = data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = self.unpad_data(padded_plaintext)
            
            return plaintext
        except TypeError as te:
            print(f"TypeError lors du déchiffrement : {te}")
            return None
        except ValueError as ve:
            print(f"ValueError lors du déchiffrement : {ve}")
            return None
        except Exception as e:
            print(f"Erreur lors du déchiffrement : {e}")
            return None

"""
Exemple d'utilisation :       
"""

# # Création d'une instance de ChiffrementAES
# aes = ChiffrementAES()

# # Génération d'une clé AES à insérer
# aes_key = aes.generate_key()
# print("La clé aes généré : ", aes_key)
# hex_aex_key = aes.get_serialized_key(aes_key)
# print("La clé aes hexa : ", hex_aex_key)
# return_to_aes_bytes_key = aes.convert_aes_key_from_hex_to_bytes(hex_aex_key)
# print("Retour à la clé d'origine : ", return_to_aes_bytes_key)

# # Insertion de la clé AES associée à un identifiant
# aes.insert_aes_key(aes_key, "identifiant_1")

# # Chiffrement de données avec la clé de l'instance
# data_to_encrypt = b"Hello, world!"
# encrypted_data = aes.encrypt(data_to_encrypt)

# # Déchiffrement des données avec la clé de l'instance
# decrypted_data = aes.decrypt(encrypted_data)

# # Vérification des données déchiffrées
# if decrypted_data == data_to_encrypt:
#     print("Les données ont été déchiffrées avec succès !")
# else:
#     print("Erreur lors du déchiffrement.")

# # Conversion de la clé AES en format hexadécimal
# aes_key_hex = aes.get_my_aes_key_serialized()

# # Insertion de la clé AES à partir de sa représentation hexadécimale
# aes.convert_aes_key_from_hex_to_bytes(aes_key_hex)
