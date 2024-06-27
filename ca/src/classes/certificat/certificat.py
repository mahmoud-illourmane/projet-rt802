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
from cryptography.x509 import load_pem_x509_certificate

# Ajoute le chemin du répertoire parent au chemin de recherche des modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class Certificat:
    """
        Classe permettant de gérer des certificats X.509, y compris la génération de certificats
        autosignés, la création de certificats signés par une autorité de certification (CA),
        la révocation de certificats, et plus encore.

        Attributs:
            rsa_instance (RSAInstance): Instance de RSA pour gérer les clés publiques et privées.
            cle_privee (RSAPrivateKey): Clé privée de l'instance RSA.
            cle_publique (RSAPublicKey): Clé publique de l'instance RSA.
            my_certificat (bytes): Certificat autosigné de la CA au format PEM.
            crl (list): Liste de révocation des certificats.
            country_name (str): Nom du pays pour le certificat.
            state_or_province_name (str): Nom de l'état ou de la province pour le certificat.
            locality_name (str): Nom de la localité pour le certificat.
            organization_name (str): Nom de l'organisation pour le certificat.
            common_name (str): Nom commun pour le certificat.
            
        Methods:
            check_my_certificat : Vérifie que la CA a son certificat autosigné.
            get_my_certificat : Retourne le certificat de la CA (bytes).
            get_crl : Retourne la liste de la CRL.
            generer_certificat_autosigne : Génère un certificat autosigné x509.
            creer_certificat_signe_par_ca : Génère un certificat avec les données envoyées par le vendeur.
            revoquer_certificat : Révoque un certificat et l'ajoute à la CRL.
            check_revoked_cert : Vérifie si un certificat est révoqué.
    """
    
    def __init__(self):
        from app import rsa_instance
        
        self.rsa_instance = rsa_instance
        self.cle_privee = self.rsa_instance.get_private_key()
        self.cle_publique = self.rsa_instance.get_my_pub_key()
        
        self.my_certificat = None
        self.crl = []
        
        self.country_name = "FR"
        self.state_or_province_name = "Marne"
        self.locality_name = "REIMS"
        self.organization_name = "IM-CORP"
        self.common_name = "mahmoud-illourmane.fr"
    
    def check_my_certificat(self):
        """
            Cette méthode vérifie si le certificat autosigné de 
            la CA existe.
            
            Returns:
                True: Certificat existe.
                False: Certificat n'existe pas.
        """
        if self.my_certificat is None:
            return False
        return True
    
    def get_my_certificat(self):
        """
            Cette méthode retoure le certificat autosigné de la CA.
        """
        return self.my_certificat
    
    def get_crl(self):
        """
            Retourne la CRL.    

        Returns:
            dict: Le dictionnaire
        """
        return self.crl
    
    def generer_certificat_autosigne(self, duree_validite_annees=1):
        """
            Génère un certificat x509 autosigné.

            Args:
                duree_validite_annees (int): Durée de validité du certificat en années (par défaut 1).

            Returns:
                bytes: Le certificat généré au format PEM.
        """

        # Définition du nom du sujet et de l'émetteur du certificat (CA elle même)
        sujet = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_name),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state_or_province_name),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])
        emetteur = sujet  # Certificat autosigné

        # Construction du certificat
        cert = x509.CertificateBuilder().subject_name(
            sujet
        ).issuer_name(
            emetteur
        ).public_key(
            self.cle_publique
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=duree_validite_annees * 365)
        ).add_extension(    # Certificat pour la CA
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.cle_publique),
            critical=False,
        ).sign(self.cle_privee, hashes.SHA256(), default_backend())

        # Sérialisation du certificat
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

        self.my_certificat = cert_pem
        return cert_pem
    
    def creer_certificat_signe_par_ca(self, cle_privee_ca, cle_publique_client: RSAPublicKey, data_user_json: dict, duree_validite_annees=1, expired=False) -> Union[bytes, None]:
        """
        Crée un certificat X.509 signé par l'autorité de certification (CA).

        Args:
            cle_privee_ca (RSAPrivateKey): Clé privée de l'autorité de certification utilisée pour signer le certificat.
            cle_publique_client (RSAPublicKey): Clé publique du client pour laquelle le certificat est créé.
            data_user_json (dict): Données de l'utilisateur pour le certificat.
            duree_validite_annees (int): Durée de validité du certificat en années (par défaut 1).
            expired (bool): Indique si le certificat doit être créé comme expiré (scénario projet).

        Returns:
            bytes: Le certificat généré au format PEM.
            ou
            None: En cas d'erreur
        """
        try:
            if not isinstance(cle_publique_client, RSAPublicKey):
                print("ERREUR: La clé publique doit être de type RSAPublicKey.")
                return None
            
            # Définition du nom du sujet du certificat
            sujet_nom = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, data_user_json['country_name']),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, data_user_json['state_or_province_name']),
                x509.NameAttribute(NameOID.LOCALITY_NAME, data_user_json['locality_name']),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, data_user_json['organization_name']),
                x509.NameAttribute(NameOID.COMMON_NAME, data_user_json['common_name']),
            ])

            # Définition du nom de l'émetteur (CA)
            emetteur_nom = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_name),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state_or_province_name),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization_name),
                x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
            ])

            # Calculer les dates de validité
            not_valid_before = datetime.now(timezone.utc) if not expired else datetime.now(timezone.utc) - timedelta(days=1)
            not_valid_after = datetime.now(timezone.utc) + timedelta(days=duree_validite_annees * 365) if not expired else datetime.now(timezone.utc) - timedelta(days=1)

            # Construction du certificat
            cert = x509.CertificateBuilder().subject_name(
                sujet_nom
            ).issuer_name(
                emetteur_nom
            ).public_key(
                cle_publique_client
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                not_valid_before
            ).not_valid_after(
                not_valid_after
            ).add_extension(    # Définit le certificat comme non-CA
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).add_extension(    # Ajoute un identifiant unique pour la clé publique du sujet
                x509.SubjectKeyIdentifier.from_public_key(cle_publique_client),
                critical=False,
            ).sign(cle_privee_ca, hashes.SHA256(), default_backend())

            # Sérialise le certificat
            cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

            return cert_pem
        except ValueError as e:
            print("Erreur:", e)
            return None
        except InvalidSignature as e:
            print("Erreur de signature:", e)
            return None
        except Exception as e:
            print("Erreur inattendue:", e)
            return None   
        
    def convert_bytes_certificat_to_str(self, certificat: bytes) -> Union[str, None]:
        """
            Cette méthode permet de convertir un certifcat de type bytes
            en certificat str pour le transfert dans le réseau.
        Args:
            certificat (bytes): Le certificat à convertir.

        Returns:
            str: le certificat encodé sous forme de chaînes de caractères.
            ou
            None: En cas d'erreur.
        """
        try:
            cert_str = certificat.decode('utf-8')
        except Exception as e:
            print("Erreur lors de la conversion du certificat :\n", e)
            return None
        return cert_str
    
    def get_serial_number_certificat(self, certificat: bytes) -> Union[int, None]:
        """
            Cette méthode retourne le serial_number d'un certificat.
            
            Args:
                certificat (bytes): Le certificat au format bytes
            
            Returns:
                serial_number (int): Le numéro de série.
                or
                None: En cas d'erreur.
        """
        try:
            cert = load_pem_x509_certificate(certificat, default_backend())
            return cert.serial_number
        except Exception as e:
            print("Erreur lors de la récupration du numéro de serie du certificat.")
            return None
    
    def revoquer_certificat(self, certificat: bytes) -> bool:
        """
            Révoque un certificat en l'ajoutant à la liste de révocation des certificats (CRL).
            
            Args:
                certificat (bytes): Le certificat à révoquer.
        """
        if not isinstance(certificat, bytes):
            print("certificat doit être de type bytes.")
            return False
        
        date_revoque = datetime.now(timezone.utc)  # La date de révocation.
        try:
            cert = x509.load_pem_x509_certificate(certificat, default_backend())
            serial_number = cert.serial_number 
        except Exception as e:
            print("ERREUR : Erreur lors de la tentative de révocation.")
            return False
        
        # Informations du certificat révoqué
        new_ = {
            "serial_number": serial_number,
            "date_revoque": date_revoque
        }
        # Ajout du certificat à la CRL
        self.crl.append(new_) 
        
        print(f"Certificat révoqué avec succès : {serial_number}")
        return True
    
    def check_revoked_cert(self, serial_number) -> bool:
        """
            Cette méthode vérifie si un certificat ce trouve dans la CRL.
            Args:
                serial_number (int): le numéro de serie du certificat

            Returns:
                bool: True | False
        """
        for cert_info in self.crl:
            if int(cert_info["serial_number"]) == int(serial_number):
                return True  # Le certificat est révoqué
        
        return False

# # Créer une instance de la classe Certificat
# certificat = Certificat()

# # Générer un certificat autosigné pour un domaine spécifique
# certificat_pem = certificat.generer_certificat_autosigne()

# # Enregistrer le certificat dans un fichier
# with open("certificate.pem", "wb") as f:
#     f.write(certificat_pem)

# print("Certificat autosigné généré et enregistré dans 'certificate.pem'")
