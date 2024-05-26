import os
import sys
import requests

# Ajoute le chemin du répertoire parent au chemin de recherche des modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.tools.tools import *

class ChiffrementRSA:

    def __init__(self):
        self.ca = str(os.getenv("CA_GET_PUB_KEY"))
        self.seller = str(os.getenv("SELLER_GET_PUB_KEY"))
        self.dossier_cles = os.path.dirname(__file__)
        self.create_empty_files()

    def create_empty_files(self):
        """
        Crée les fichiers vides s'ils n'existent pas déjà.
        """
        ca_path = os.path.join(self.dossier_cles, self.ca)
        seller_path = os.path.join(self.dossier_cles, self.seller)

        if not os.path.exists(ca_path):
            with open(ca_path, 'w') as f:
                pass  # Fichier vide

        if not os.path.exists(seller_path):
            with open(seller_path, 'w') as f:
                pass  # Fichier vide

    def generer_cles(self, taille_cle=2048, force=False):
        """
        Génère une paire de clés RSA et les stocke dans le dossier "encryption".

        Args:
            taille_cle (int): La taille de la clé en bits (par défaut 2048).
            force (bool): Force la génération de nouvelles clés même si des clés existent déjà (par défaut False).

        Returns:
            0, -1
        """
        try:
            if not force and os.path.exists(os.path.join(self.dossier_cles, "public_key.pem")):
                print(f"{COLOR_RED}Des clés existent déjà.{COLOR_END}")
                return -1

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=taille_cle,
                backend=default_backend()
            )

            public_key = private_key.public_key()

            with open(os.path.join(self.dossier_cles, "private_key.pem"), "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(os.path.join(self.dossier_cles, "public_key.pem"), "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

        except Exception as e:
            print(f"{COLOR_RED}Une erreur s'est produite lors de la génération des clés : {str(e)}{COLOR_END}")
        
        return 0
    
    def a_paire_de_cles_rsa(self):
        """
        Vérifie si une paire de clés RSA existe déjà.

        Returns:
            bool: True si une paire de clés existe, False sinon.
        """
        if os.path.exists(os.path.join(self.dossier_cles, "public_key.pem")) and \
           os.path.exists(os.path.join(self.dossier_cles, "private_key.pem")):
            return True
        return False
    
    def charger_cle_publique(self):
        """
        Charge la clé publique depuis le fichier "public_key.pem".

        Returns:
            La clé publique RSA
        """
        with open(os.path.join(self.dossier_cles, "public_key.pem"), "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        return public_key

    def charger_str_cle_publique_ca(self):
        """
        Retourne la clé publique de la CA.

        Returns:
            La clé publique RSA sous forme de chaîne de caractères ou -1 en cas d'erreur.
        """
        try:
            with open(os.path.join(self.dossier_cles, str(os.getenv("CA_GET_PUB_KEY"))), "rb") as f:
                public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
                public_key_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
            return public_key_pem
        except Exception as e:
            print(f"Une erreur s'est produite lors du chargement de la clé publique de la CA : {e}")
            return -1
    
    def charger_str_cle_publique_seller(self):
        """
            Retourne la clé publique du vendeur.

            Returns:
                La clé publique RSA sous forme de chaîne de caractères ou -1 en cas d'erreur.
        """
        try:
            with open(os.path.join(self.dossier_cles, str(os.getenv("SELLER_GET_PUB_KEY"))), "rb") as f:
                public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
                if isinstance(public_key, RSAPublicKey):  # Vérifie si la clé chargée est bien de type RSAPublicKey
                    public_key_pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8')
                    return public_key_pem
                else:
                    print("La clé chargée n'est pas une clé publique RSA valide.")
                    return -1
        except Exception as e:
            print(f"Une erreur s'est produite lors du chargement de la clé publique du vendeur : {e}")
            return -1

    def charger_cle_privee(self):
        """
        Charge la clé privée depuis le fichier "private_key.pem".

        Returns:
            La clé privée RSA
        """
        with open(os.path.join(self.dossier_cles, "private_key.pem"), "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        return private_key

    def crypter(self, message, cle_publique):
        """
        Chiffre un message avec la clé publique fournie.

        Args:
            message (bytes): Le message à crypter.
            cle_publique (RSA): La clé publique RSA.

        Returns:
            Le message chiffré (bytes)
        """
        return cle_publique.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypter(self, message_chiffre, cle_privee):
        """
        Déchiffre un message avec la clé privée fournie.

        Args:
            message_chiffre (bytes): Le message chiffré à décrypter.
            cle_privee (RSA): La clé privée RSA.

        Returns:
            Le message déchiffré (bytes)
        """
        return cle_privee.decrypt(
            message_chiffre,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
    @staticmethod
    def ecrire_pub_key_ca(pubKey):
        """
            Cette méthode permet d'enregistrer la clé publique de la ca sur le client.
        """
        try:
            # Chemin du fichier
            file_path = os.path.join(os.path.dirname(__file__), str(os.getenv("CA_GET_PUB_KEY")))

            # Enregistrer la clé publique dans un fichier
            with open(file_path, "w") as f:
                f.write(pubKey)

            print(f"{COLOR_GREEN}Clé publique récupérée avec succès et enregistrée dans pub_key_ca.pem{COLOR_END}")
            return 0
        except requests.exceptions.RequestException as e:
            print(f"{COLOR_RED}Une erreur s'est produite lors de la requête : {e} {COLOR_END}")
            return None
    
    @staticmethod
    def ecrire_pub_key_seller(pubKey):
        """
            Cette méthode permet d'enregistrer la clé publique de la ca sur le client.
        """
        try:
            # Chemin du fichier
            file_path = os.path.join(os.path.dirname(__file__), str(os.getenv("SELLER_GET_PUB_KEY")))

            # Enregistrer la clé publique dans un fichier
            with open(file_path, "w") as f:
                f.write(pubKey)

            print(f"{COLOR_GREEN}Clé publique récupérée avec succès et enregistrée dans pub_key_seller.pem{COLOR_END}")
            return 0
        except requests.exceptions.RequestException as e:
            print(f"{COLOR_RED}Une erreur s'est produite lors de la requête : {e} {COLOR_END}")
            return None



# Exemple

# chiffrement = ChiffrementRSA()

# # Générer une paire de clés
# # Première fois seulement
# chiffrement.generer_cles()

# # Charger les clés
# cle_publique = chiffrement.charger_cle_publique()
# cle_privee = chiffrement.charger_cle_privee()

# # Chiffrer un message
# message = b"Ceci est un message secret"
# message_chiffre = chiffrement.crypter(message, cle_publique)

# print(f"Message crypter : {message_chiffre}")
# # Décrypter le message
# message_dechiffre = chiffrement.decrypter(message_chiffre, cle_privee)

# # Vérifier le message déchiffré
# assert message == message_dechiffre
# print(f"Message décrypter : {message_dechiffre}")


