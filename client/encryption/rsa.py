import os
import sys
import requests

# Ajoute le chemin du répertoire parent au chemin de recherche des modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from config import *
from src.classes.tools import *

class ChiffrementRSA:

    def __init__(self):
        self.ca = CA_ADDRESS
        self.dossier_cles = os.path.join(os.path.dirname(__file__), "..", "encryption")
        if not os.path.exists(self.dossier_cles):
            os.makedirs(self.dossier_cles)

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

    def recuperer_pub_ca(self):
        """
        Cette méthode envoie une requête à CA pour récupérer sa clé publique.
        """
        url = self.ca + CA_GET_PUB_KEY

        try:
            response = requests.get(url)
            response.raise_for_status()  # Si la réponse n'est pas OK, lève une exception

            # Chemin du fichier
            file_path = os.path.join(os.path.dirname(__file__), "public_key_ca.pem")

            # Enregistrer la clé publique dans un fichier
            with open(file_path, "w") as f:
                f.write(response.text)

            print(f"{COLOR_GREEN}Clé publique récupérée avec succès et enregistrée dans pub_key_ca.pem{COLOR_END}")
            return response.text
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


