import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import base64

# Ajoute le chemin du répertoire parent au chemin de recherche des modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'encryption')))

class ChiffrementRSA:
    """
        Cette classe se charge de générer et gérer les clés RSA.
        Les clés RSA des autres entités seront stocké dans un dictionnaire.
    """

    def __init__(self):
        self.cle_privee = self.generer_cles()
        self.cle_publique = self.cle_privee.public_key()
        self.rsa_keys = {}

    def generer_cles(self, taille_cle=2048):
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

    def get_my_pub_key(self):
        """
            Retourne la clé publique du client
        """
        return self.cle_publique
    
    def get_my_pub_key_serialized(self):
        """
        Retourne la clé publique du client en format PEM sérialisée.

        Returns:
            str: La clé publique en format PEM sérialisée.
            None: En cas d'erreur.
        """
        try:
            pub_key_serialized = self.cle_publique.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            return pub_key_serialized
        except Exception as e:
            print(f"Erreur lors de la sérialisation de la clé publique : {e}")
            return None

    def receive_pub_key(self, pub_key_pem):
        """
        Désérialise une clé publique PEM reçue en un objet RSAPublicKey.

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
            return pub_key
        except Exception as e:
            print(f"Erreur lors de la désérialisation de la clé publique : {e}")
            return None

    def insert_rsa_key(self, rsa_key, identifier):
        """
            Insère une clé RSA associée à un identifiant dans le dictionnaire.

            Args:
                rsa_key (RSAPrivateKey): La clé RSA à insérer.
                identifier (str): L'identifiant associé à la clé.
        """
        self.rsa_keys[identifier] = rsa_key

    def get_rsa_key(self, identifier, as_text=False):
        """
            Récupère la clé publique RSA associée à un identifiant dans le dictionnaire.

            Args:
                identifier (str): L'identifiant de la clé à récupérer.
                as_text (bool): Si True, retourne la clé en version texte. Par défaut False.

            Returns:
                RSAPublicKey or str or None: La clé RSA associée à l'identifiant ou sa version texte.
                None si la clé n'est pas trouvée ou s'il y a une erreur.
        """
        key = self.rsa_keys.get(identifier)
        if key:
            try:
                if as_text:
                    return key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8')
                return key
            except Exception as e:
                print(f"Erreur lors de la récupération de la clé publique en version texte : {e}")
                return -1
        else:
            print("get_rsa_key: Clé non trouvée pour l'identifiant spécifié.")
            return None
    
    def exporter_cle_publique_str(self):
        """
            Exporte la clé publique au format PEM.
            Facilement lisible.
            
            Returns:
                str: La clé publique au format PEM
        """
        public_key_pem = self.cle_publique.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return public_key_pem

    def exporter_cle_privee(self):
        """
            Exporte la clé privée au format PEM.

            Returns:
                cle_privee: format brute.
        """
        return self.cle_privee

    def crypter(self, message, cle_publique=None, encode_base64=False):
        """
        Chiffre un message avec la clé publique fournie ou la clé publique de l'instance.

        Args:
            message (bytes): Le message à crypter.
            cle_publique (RSA): La clé publique RSA (optionnelle).
            encode_base64 (bool): Indique si le résultat doit être encodé en Base64.

        Returns:
            bytes or str: Le message chiffré ou encodé en Base64, selon la valeur de encode_base64.
            None: en cas d'erreur
        """
        try:
            if cle_publique is None:
                cle_publique = self.cle_publique

            ciphertext = cle_publique.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            if encode_base64:
                # Convertir les octets chiffrés en Base64
                encoded_cipher = base64.b64encode(ciphertext).decode('utf-8')
                return encoded_cipher
            else:
                return ciphertext
        except Exception as e:
            print(f"Erreur lors du chiffrement du message : {e}")
            return None

    def decrypt_cipher_base64(self, encoded_cipher_base64):
        """
            Cette méthode est utilisé lorsque des données encodé
            en base64 sont reçu.
 
        Args:
            encoded_cipher_base64 : la châine crypter et encodé en base64

        Returns:
            aes_cipher: la chaîne crypter en RSA.
        """
        try:
            rsa_cipher = base64.b64decode(encoded_cipher_base64)
            return rsa_cipher
        except (Exception) as e:
            print(f"Erreur lors du décodage base64: {e}")
            return None

    def decrypter(self, message_chiffre, cle_privee=None):
        """
            Déchiffre un message avec la clé privée fournie ou la clé privée de l'instance.

            Args:
                message_chiffre (bytes): Le message chiffré à décrypter.
                cle_privee (RSA): La clé privée RSA (optionnelle).

            Returns:
                bytes: Le message déchiffré
                None: +Message d'erreur si la clé privée ou le déchiffrement échoue.
        """
        try:
            if cle_privee is None:
                cle_privee = self.cle_privee

            plaintext = cle_privee.decrypt(
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

# chiffrement = ChiffrementRSA()

# # Chiffrer un message
# message = b"Ceci est un message secret"
# message_chiffre = chiffrement.crypter(message)
# print(f"Message crypté : {message_chiffre}")

# # Décrypter le message
# message_dechiffre = chiffrement.decrypter(message_chiffre)
# print(f"Message déchiffré : {message_dechiffre}")

# # Vérifier le message déchiffré
# assert message == message_dechiffre
