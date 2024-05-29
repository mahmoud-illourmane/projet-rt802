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
                aes_keys (dict): Un dictionnaire pour stocker les clés AES associées à des identifiants.
        """
        self.aes_keys = {}

    def generate_key(self):
        """
            Génère une clé AES de 256 bits aléatoire.
        """
        return os.urandom(32)

    def insert_aes_key(self, aes_key: bytes, identifiant: str):
        """
            Insère une clé AES associée à un identifiant dans le dictionnaire des clés.

            Args:
                aes_key (bytes): La clé AES à insérer.
                identifiant (str): L'identifiant associé à la clé.

            Raises:
                TypeError: Si aes_key n'est pas de type bytes ou identifiant n'est pas de type str.
        """
        # Vérifie que aes_key est bien de type bytes
        if not isinstance(aes_key, bytes):
            raise TypeError("La clé AES doit être de type bytes.")
        
        # Vérifie que identifiant est bien de type str
        if not isinstance(identifiant, str):
            raise TypeError("L'identifiant doit être de type str.")
        
        # Vérifie si l'identifiant existe pas déjà dans le dictionnaire
        if identifiant not in self.aes_keys:
            # Insère la clé AES dans le dictionnaire
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
    
    def aes_key_exist(self, identifiant: str) -> bool:
        """
            Cette méthode vérifie que une clé existe dans le dictionnaire.

        Args:
            identifiant (str): l'identifiant à chercher.

        Returns:
            bool: True or False
        """
        if self.aes_keys.get(identifiant):
            return True
        return False
    
    
    def get_all_aes_keys(self) -> dict:
        """
            Retourne tout le dictionnaire des clés AES en format hexadécimal.
            Destiné à être utiliser pour l'affichage.
            
            Returns:
                dict: Le dictionnaire contenant toutes les clés AES en format hexadécimal.
        """
        return {identifiant: key.hex() for identifiant, key in self.aes_keys.items()}
        
    def get_aes_key_dict_serialized(self, identifiant: str) -> Union[str, None]:
        """
            Retourne la clé AES en format hexadécimal.
            Utile pour de l'affichage ou de l'envoi.
            
            Returns:
                str: La clé AES en format hexadécimal.
                ou
                None: En cas d'erreur.
        """
        try:
            aes_key = self.get_aes_key(identifiant)
            if aes_key is not None:
                serialized_key = aes_key.hex()
                
            return serialized_key
        except TypeError as te:
            print(f"Erreur lors de la sérialisation en hexadécimal de la clé AES (get_aes_key_dict_serialized) :\n{te}")
            return None

    def get_serialized_key(self, aes_key: bytes) -> Union[str, None]:
        """
            Retourne une clé AES au format hexadécimal.
            
            Args:
                aes_key (bytes) : La clé AES au format bytes.
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
            print(f"Erreur lors de la conversion de la clé AES (convert_aes_key_from_hex_to_bytes) :\n{ve}")
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

    def encrypt(self, data: bytes, aes_key: bytes, use_base64=False) -> Union[bytes, str, None]:
        """
            Chiffre les données avec AES-256 en mode CBC avec padding PKCS#7.

            Args:
                data (bytes): Les données à chiffrer.
                aes_key (bytes): La clé AES à utiliser pour le chiffrement. Si None, utilise la clé de l'instance.
                use_base64 (bool, facultatif): Indique si les données chiffrées doivent être converties en base64 en une chaîne de caractères Unicode. Par défaut, False.

            Returns:
                bytes: Les données chiffrées, incluant l'IV au début. 
                ou
                str: Converti les données chiffrées en base64 en une chaîne de caractères Unicode si use_base64=True.
                ou 
                None: En cas d'erreur.
        """
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padded_data = self.pad_data(data)
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_data = iv + ciphertext
            if use_base64:
                return base64.b64encode(encrypted_data).decode('utf-8')
            else:
                return encrypted_data
            
        except ValueError as ve:
            print(f"Erreur de valeur lors du chiffrement (encrypt) :\n{ve}")
            return None
        except Exception as e:
            print(f"Erreur lors du chiffrement (encrypt) :\n{e}")
            return None
        
    def decrypt(self, data, key: bytes, use_base64=False):
        """
            Déchiffre les données avec AES-256 en mode CBC, puis supprime le padding PKCS#7.

            Args:
                data (bytes or str): Les données chiffrées, incluant l'IV au début.
                Si use_base64 est True, (data) doit être une chaîne de caractères (str) encodée en base64.
                key (bytes): La clé AES à utiliser pour le déchiffrement.
                use_base64 (bool, facultatif): Indique si les données chiffrées sont encodées en base64. Par défaut, False.

            Returns:
                bytes: Les données déchiffrées.
        """
        try:
            if use_base64:
                # Si les données sont encodées en base64, les décoder en bytes
                data = base64.b64decode(data)
            
            iv = data[:16]
            ciphertext = data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = self.unpad_data(padded_plaintext)
            
            return plaintext
        except TypeError as te:
            print(f"TypeError lors du déchiffrement (decrypt) :\n{te}")
            return None
        except ValueError as ve:
            print(f"ValueError lors du déchiffrement (decrypt) :\n{ve}")
            return None
        except Exception as e:
            print(f"Erreur lors du déchiffrement (decrypt) :\n{e}")
            return None

"""
Exemple d'utilisation :       
"""

# # Exemple 1
# message_a_chiffrer = b'BONJOUR A TOUS.'

# # Création d'une instance de ChiffrementAES
# aes = ChiffrementAES()

# # Génération de deux clés AES.
# aes_key_1 = aes.generate_key()

# message_chiffre = aes.encrypt(message_a_chiffrer, aes_key_1, True)
# message_dechifre = aes.decrypt(message_chiffre, aes_key_1, True)

# if message_a_chiffrer == message_dechifre:
#     print("ok")
# else:
#     print('KO')

# Exemple 2
# message_a_chiffrer = b'BONJOUR A TOUS.'

# # Création d'une instance de ChiffrementAES
# aes = ChiffrementAES()

# # Génération de deux clés AES.
# aes_key_1 = aes.generate_key()
# aes_key_2 = aes.generate_key()

# # Inserer la clé AES dans le dictionnaire des clés.
# aes.insert_aes_key(aes_key_1, "aes_key_1")

# # Afficher le dictionnaire
# dict = aes.get_all_aes_keys()
# print(dict)

# Exemple 3

# # Création d'une instance de ChiffrementAES
# aes = ChiffrementAES()

# # Génération d'une clé AES
# aes.generate_key("my")

# # Récupération de la clé AES
# aes_key = aes.get_aes_key("my")
# if aes_key is None:
#     print("Erreur lors de la récuperation de la clé AES.")
#     exit(-1)
# print("La clé aes généré :\n", aes_key, "\n")

# # Conversion de la clé AES en Hexa.
# hex_aex_key = aes.get_serialized_key(aes_key)
# print("La clé aes en hexa :\n", hex_aex_key, "\n")

# return_to_aes_bytes_key = aes.convert_aes_key_from_hex_to_bytes(hex_aex_key)
# if return_to_aes_bytes_key is None:
#     print("Erreur les données cryptés ne sont pas en bytes.")
#     exit(-1)
# print("Retour à la clé d'origine : ", return_to_aes_bytes_key)

# # Chiffrement de données
# data_to_encrypt = b"Hello, world!"
# encrypted_data = aes.encrypt(data_to_encrypt, return_to_aes_bytes_key)
# if encrypted_data is None:
#     print("Erreur les données cryptés ne sont pas en bytes.")
#     exit(-1)
    
# # Déchiffrement des données
# decrypted_data = aes.decrypt(encrypted_data, return_to_aes_bytes_key)

# # Vérification des données déchiffrées
# if decrypted_data == data_to_encrypt:
#     print("Les données ont été déchiffrées avec succès !")
# else:
#     print("Erreur lors du déchiffrement.")