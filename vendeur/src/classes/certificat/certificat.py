import os, sys
from datetime import datetime, timezone, timedelta
from typing import Union  # Retour de fonction [str|int]

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.exceptions import InvalidSignature

class Certificat_vendeur:
    def __init__(self):
        """
            Cette classe contiendra les certificats du vendeurs pour les scénarios.
            
            certificates: dictionnaire imbriqué qui contiendra les certificats du vendeur [Révoqué et non Révoqué] 
        """
        self.certificates = {}
        
    def insert_certificat(self, certificat: bytes, identifiant: str, revoked=False) -> bool:
        """
            Cette méthode permet d'ajouter un certificat au dictionnaire des certificats.
            
            Args:
                certificat (bytes): Le certificat à insérer.
                identifiant (str): Un identifiant unique.
            
            Returns:
                Bool
        """
        if identifiant not in self.certificates:
            self.certificates[identifiant] = {
                "certificat": certificat,
                "revoked": revoked
            }
            return True
        else:
            print(f"L'identifiant {identifiant} est déjà présent dans le dictionnaire.")
            return False 
        
    def verifier_certificat(self, cert_pem, ca_public_key):
        """
            Vérifie qu'un certificat est bien signé par la CA.

            Args:
                cert_pem (bytes): Le certificat à vérifier au format PEM.
                ca_public_key (RSAPublicKey): La clé publique de la CA.

            Returns:
                bool: True si le certificat est valide et signé par la CA, False sinon.
        """
        try:
            # Charger le certificat
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

            # Vérifier la signature du certificat en utilisant la clé publique de la CA
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )

            return True
        except Exception as e:
            print("Erreur de vérification du certificat:", e)
            return False