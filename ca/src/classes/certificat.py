import os
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from encryption.rsa import ChiffrementRSA

class Certificat:

    @staticmethod
    def generer_certificat(demande_certificat, chemin_certificat, chiffrement):
        # Charger la clé privée
        cle_privee = chiffrement.charger_cle_privee()
        
        # Charger la clé publique
        cle_publique = chiffrement.charger_cle_publique()

        # Créer un objet CertificateSigningRequest à partir de la demande de certificat
        csr = x509.load_pem_x509_csr(demande_certificat, default_backend())

        # Construire le certificat
        builder = x509.CertificateBuilder()

        # Remplir les informations du sujet avec celles de la demande de certificat
        builder = builder.subject_name(csr.subject)

        # Ajouter le sujet alternatif si présent
        if csr.extensions.get_extension_for_class(x509.SubjectAlternativeName):
            builder = builder.add_extension(
                csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
                critical=False
            )

        # Utiliser la clé publique de la demande de certificat
        builder = builder.public_key(cle_publique)

        # Ajouter une date de début et une durée de validité
        builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))

        # Signer le certificat avec la clé privée
        certificate = builder.sign(
            private_key=cle_privee,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        # Écrire le certificat dans un fichier
        with open(chemin_certificat, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        print("Certificat généré avec succès.")
