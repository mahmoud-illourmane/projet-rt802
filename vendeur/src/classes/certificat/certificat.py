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
            certificat_to_send: Variable qui contiendra le certificat à envoyé à chaque demande du client.
        """
        self.certificates = {}
        self.certificat_to_send = None
    
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
    
    def get_certificat(self, cert_id: str) -> Union[bytes, None]: 
        """
            Cette méthode retourne un certificat.
            
            Args:
                cert_id (str): L'identifiant du certificat.
            Returns:
                certificat (bytes): Le certificat.
                None: Si il n'existe pas.
        """
        certificat_data = self.certificates.get(cert_id)
        if certificat_data is not None:
            return certificat_data["certificat"]
        else:
            return None
    
    def get_certificate_to_send(self) -> Union[bytes, None]:
        """
            Cette méthode renvoi le certificat à envoyer au client en utilisant
            l'attribut d'instance 'certificat_to_send'
            
            Returns:
                certificate (bytes): le certificat.
                ou
                None: En cas d'erreur.
        """
        if self.certificat_to_send == None:
            return None
        return self.certificat_to_send
    
    def get_all_certificates(self) -> dict:
        """
            Cette méthode permet de retourner un dictionnaire de chaque identifiant de certificat 
            et de si il est révoqué ou pas.
            
            Returns:
                dict: Un dictionnaire contenant les informations des certificats.
        """
        return {identifiant: {"identifiant": identifiant, "revoked": data['revoked']} for identifiant, data in self.certificates.items()}
    
    
    def define_cert_to_send(self, cert_id):
        """
            Cette méthode permet de définir le certificat a envoyer par défaut.
            
            Args:
                cert_id (str): Identifiant déjà présent dans le dictionnaire.
            
            Returns:
                Bool: True | False
        """
        cert = self.get_certificat(cert_id)
        if cert is None:
            return None
        self.certificat_to_send = cert
    
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
            # Charge le certificat
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

            # Vérifie la signature du certificat en utilisant la clé publique de la CA
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