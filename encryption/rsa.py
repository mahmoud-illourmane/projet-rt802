import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import base64
from typing import Union  # Retour de fonction [str|int]

# Ajoute le chemin du répertoire parent au chemin de recherche des modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'encryption')))

class ChiffrementRSA:
    """
        Cette classe se charge de générer et gérer les clés RSA.
        Les clés RSA des autres entités seront stocké dans un dictionnaire.
    """

    def __init__(self):
        """
            Initialise une nouvelle instance de la classe ChiffrementRSA.

            La méthode génère une paire de clés RSA et initialise un dictionnaire pour stocker d'autres clés publique RSA.

            Attributes:
                private_key (RSAPrivateKey): La clé privée RSA générée.
                public_key (RSAPublicKey): La clé publique RSA correspondant à la clé privée.
                rsa_keys (dict): Un dictionnaire pour stocker d'autres clés publique RSA associées à des identifiants.
        """
        self.private_key = self.generate_keys()
        self.public_key = self.private_key.public_key()
        self.rsa_keys = {}

    def generate_keys(self, taille_cle=2048):
        """
            Génère une clé privée RSA.

            Args:
                taille_cle (int): La taille de la clé en bits (par défaut 2048).

            Returns:
                RSAPrivateKey: La clé privée RSA
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=taille_cle,
            backend=default_backend()
        )
        
        return private_key

    def get_private_key(self):
        """
            Exporte la clé privée dans son format natif.

            Returns:
                RSAPrivateKey: La clé privée RSA dans son format natif.
        """
        return self.private_key

    def get_my_pub_key(self):
        """
            Retourne la clé publique.
        """
        return self.public_key
    
    def get_my_pub_key_pem(self):
        """
            Retourne la clé publique au format PEM.

            Returns:
                str: La clé publique en format PEM.
                None: En cas d'erreur.
        """
        try:
            pub_key_serialized = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            return pub_key_serialized
        except Exception as e:
            print(f"Erreur lors de la sérialisation de la clé publique : {e}")
            return None

    def receive_pub_key_pem(self, pub_key_pem:str):
        """
            Cette fonction reçoit une clé publique au format PEM et renvoie un objet RSAPublicKey.

            Args:
                pub_key_pem (str): La clé publique en format PEM.

            Returns:
                RSAPublicKey: L'objet de clé publique RSA.
                None: En cas d'erreur.
        """
        try:
            pub_key = serialization.load_pem_public_key(
                pub_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            if isinstance(pub_key, RSAPublicKey):
                return pub_key
            else:
                raise TypeError("La clé publique n'est pas une clé RSA")
        except Exception as e:
            print(f"Erreur lors de la désérialisation de la clé publique (receive_pub_key_pem) : {e}")
            return None

    def insert_pub_key(self, pub_key: RSAPublicKey, identifiant: str):
        """
            Insère une clé RSA associée à un identifiant dans le dictionnaire des clés.

            Args:
                rsa_key (RSAPublicKey): La clé RSA à insérer.
                identifiant (str): L'identifiant associé à la clé.
        """
        # Vérifie si rsa_key est une instance de RSAPublicKey
        if not isinstance(pub_key, RSAPublicKey):
            raise TypeError("La clé fournie n'est pas une clé RSA publique.")

        # Vérifie si la clé est bien formatée
        if not hasattr(pub_key, 'public_bytes'):
            raise ValueError("La clé RSA ne possède pas la méthode public_bytes.")
        
        # Insertion de la clé
        self.rsa_keys[identifiant] = pub_key

    def get_pub_key(self, identifiant: str, as_pem=False) -> Union[RSAPublicKey, str, None]:
        """
            Retourne la clé publique associée à un identifiant dans le dictionnaire des clés.

            Args:
                identifiant (str): L'identifiant de la clé à récupérer.
                as_pem (bool): Si True, retourne la clé au format PEM sous forme de texte. Par défaut False.

            Returns:
                RSAPublicKey: La clé publique associée à l'identifiant.
                PEM: La clé RSA représenté au format PEM.
                None: Si la clé n'est pas trouvée ou s'il y a une erreur.
        """
        
        # Utilisation du dictionnaire de clés pour récupérer la clé avec l'identifiant
        key = self.rsa_keys.get(identifiant)
        if key:
            try:
                if as_pem:  # Si as_pem est True on renvoi la clé au format PEM.
                    if isinstance(key, RSAPublicKey):
                        return key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ).decode('utf-8')
                    else:
                        raise TypeError("La clé n'est pas une clé RSA publique")
                # Retourner la clé au format interne RSAPublicKey
                return key
            except Exception as e:
                print(f"Erreur lors de la récupération de la clé publique : {e}")
                return None
        else:
            print("get_rsa_key: Clé non trouvée pour l'identifiant spécifié.")
            return None

    def decode_base64_encoded_rsa_cipher(self, encoded_cipher_base64) -> Union[bytes, None]:
        """
            Décode une chaîne chiffrée RSA encodée en base64 (Supprime l'encodage base64).
            
            Args:
                encoded_cipher_base64 (str): La chaîne chiffrée encodée en base64.

            Returns:
                bytes: La chaîne chiffrée RSA en bytes.
                ou
                None: None en cas d'erreur.
        """
        try:
            rsa_cipher = base64.b64decode(encoded_cipher_base64)
            return rsa_cipher
        except Exception as e:
            print(f"Erreur lors du décodage base64 (decode_base64_encoded_rsa_cipher) : {e}")
            return None
        
    def crypter(self, message: bytes, public_key=None, encode_base64=False) -> Union[bytes, str, None]:
        """
            Chiffre un message avec la clé publique fournie ou la clé publique de l'instance.

            Args:
                message (bytes): Le message à crypter.
                public_key (RSAPublicKey): La clé publique RSA (optionnelle).
                encode_base64 (bool): Indique si le résultat doit être encodé en Base64.

            Returns:
                bytes: Le message chiffré.
                ou
                str: Le message chiffré encodé en base64 si encode_base64=True.
                ou
                None: en cas d'erreur.
        """
        try:
            if public_key is None:
                public_key = self.public_key

            ciphertext = public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            if encode_base64:   # Convertir les octets chiffrés en Base64.
                encoded_cipher = base64.b64encode(ciphertext).decode('utf-8')
                return encoded_cipher
            else:   # Retourner les octets chiffrés en bytes.
                return ciphertext
            
        except ValueError as ve:
            print(f"Erreur de valeur lors du chiffrement du message : {ve}")
            return None
        except TypeError as te:
            print(f"Erreur de type lors du chiffrement du message : {te}")
            return None
        except Exception as e:
            print(f"Erreur lors du chiffrement du message : {e}")
            return None

    def decrypter(self, message_chiffre):
        """
            Déchiffre un message avec la clé privée de l'instance.

            Args:
                message_chiffre (bytes): Le message chiffré à décrypter.
            
            Returns:
                any: Le message déchiffré
                ou
                None: En cas d'erreur si le déchiffrement échoue.
        """
        try:
            plaintext = self.private_key.decrypt(
                message_chiffre,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return plaintext
        except ValueError as ve:
            print(f"Erreur de déchiffrement : {ve}")
            return None
        except Exception as e:
            print(f"Erreur lors du déchiffrement : {e}")
            return None

"""
Exemple d'utilisation :       
"""

# # Création d'un message à chiffrer
# message = b"Hello, world!"

# # Création d'une instance de la classe ChiffrementRSA
# rsa_ = ChiffrementRSA()

# # Récupération de la clé publique au format PEM
# public_key_pem = rsa_.get_my_pub_key_pem()

# # Chiffrement du message avec la clé publique
# cipher_text_base64 = rsa_.crypter(message, None, True)

# # Affichage du message chiffré
# print("\n\nMessage chiffré en base64:")
# print(cipher_text_base64)

# # Décodage du message chiffré encodé en base64
# cipher_text = rsa_.decode_base64_encoded_rsa_cipher(cipher_text_base64)
# print("\n\nMessage chiffré en bytes:")
# print(cipher_text)

# # Déchiffrement du message avec la clé privée
# decrypted_message = rsa_.decrypter(cipher_text)
# if decrypted_message is not None:
#     # Affichage du message déchiffré
#     print("\n\nMessage déchiffré:")
#     print(decrypted_message.decode('utf-8'))  # Assuming the message was a UTF-8 encoded string
