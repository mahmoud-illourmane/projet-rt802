import os, sys
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

# Ajoute le chemin du répertoire parent au chemin de recherche des modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class Certificat:
    def __init__(self):
        from app import rsa_instance
        
        self.rsa_instance = rsa_instance
        self.cle_privee = self.rsa_instance.get_private_key()
        self.cle_publique = self.rsa_instance.get_my_pub_key()
        
        self.my_certificat = None
        
        self.country_name = "FR"
        self.state_or_province_name = "Marne"
        self.locality_name = "REIMS"
        self.organization_name = "IM-CORP"
        self.common_name = "mahmoud-illourmane.fr"
        
    def generer_certificat_autosigne(self, duree_validite_annees=1):
        """
            Génère un certificat x509 autosigné.

            Args:
                duree_validite_annees (int): Durée de validité du certificat en années (par défaut 1).

            Returns:
                bytes: Le certificat généré au format PEM.
        """

        # Définition du nom du sujet et de l'émetteur du certificat
        sujet = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_name),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state_or_province_name),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])
        emetteur = sujet  # Certificat autosigné

        # Construire le certificat
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
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.cle_publique),
            critical=False,
        ).sign(self.cle_privee, hashes.SHA256(), default_backend())

        # Sérialiser le certificat
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

        self.my_certificat = cert_pem
        return cert_pem
    
    def creer_certificat_signe_par_ca(self, cle_privee_ca, cle_publique_ca, cle_publique_client, duree_validite_annees=1):
        """
            Crée un certificat X.509 signé par l'autorité de certification (CA).

            Args:
                cle_privee_ca (RSAPrivateKey): Clé privée de l'autorité de certification utilisée pour signer le certificat.
                cle_publique_ca (RSAPublicKey): Clé publique de l'autorité de certification.
                cle_publique_client (RSAPublicKey): Clé publique du client pour laquelle le certificat est créé.
                duree_validite_annees (int): Durée de validité du certificat en années (par défaut 1).

            Returns:
                bytes: Le certificat généré au format PEM.
        """

        # Définir le nom du sujet du certificat
        sujet_nom = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Marne"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"REIMS"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"IM-CORP"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Votre Client"),
        ])

        # Construire le certificat
        cert = x509.CertificateBuilder().subject_name(
            sujet_nom
        ).issuer_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Marne"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"REIMS"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"IM-CORP"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"Votre CA"),
            ])
        ).public_key(
            cle_publique_client
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=duree_validite_annees * 365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(cle_publique_client),
            critical=False,
        ).sign(cle_privee_ca, hashes.SHA256(), default_backend())

        # Sérialiser le certificat
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

        return cert_pem
    
    
# # Créer une instance de la classe Certificat
# certificat = Certificat()

# # Générer un certificat autosigné pour un domaine spécifique
# certificat_pem = certificat.generer_certificat_autosigne()

# # Enregistrer le certificat dans un fichier
# with open("certificate.pem", "wb") as f:
#     f.write(certificat_pem)

# print("Certificat autosigné généré et enregistré dans 'certificate.pem'")
