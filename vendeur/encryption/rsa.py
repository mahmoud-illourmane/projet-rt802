import os, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Ajoute le chemin du répertoire parent au chemin de recherche des modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class ChiffrementRSA:

    def __init__(self):
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
            None
        """
        if not force and os.path.exists(os.path.join(self.dossier_cles, "public_key.pem")):
            print("Des clés existent déjà dans le dossier.")
            return

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=taille_cle,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        with open(os.path.join(self.dossier_cles, "public_key.pem"), "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        with open(os.path.join(self.dossier_cles, "private_key.pem"), "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
    def charger_cle_publique(self):
        """
        Charge la clé publique depuis le fichier "public_key.pem".

        Returns:
            La clé publique RSA
        """
        with open(os.path.join(self.dossier_cles, "public_key.pem"), "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        return public_key

    def exporter_cle_publique_pem(self):
        """
        Exporte la clé publique au format PEM.

        Returns:
            str: La clé publique au format PEM
        """
        public_key = self.charger_cle_publique()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        return public_key_pem
        
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
        ciphertext = cle_publique.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypter(self, message_chiffre, cle_privee):
        """
        Déchiffre un message avec la clé privée fournie.

        Args:
            message_chiffre (bytes): Le message chiffré à décrypter.
            cle_privee (RSA): La clé privée RSA.

        Returns:
            Le message déchiffré (bytes)
        """
        plaintext = cle_privee.decrypt(
            message_chiffre,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext


"""
    Exemple d'utilisation :       
"""

chiffrement = ChiffrementRSA()
public_key = chiffrement.charger_cle_publique()


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

# print(f"Message crypté : {message_chiffre}")

# # Décrypter le message
# message_dechiffre = chiffrement.decrypter(message_chiffre, cle_privee)

# # Vérifier le message déchiffré
# assert message == message_dechiffre
# print(f"Message déchiffré : {message_dechiffre}")
