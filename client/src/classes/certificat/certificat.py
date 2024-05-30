from typing import Union
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone

class Certificat:
   
    def __init__(self):
        """
            Cette classe sert juste à stocker temporairement le certificat du vendeur pour
            pouvoir afficher le résultat de la vérification du certificat coté Vue.js
            
            certificat (bytes): le certificat à stocker.
            response_ca (bool) = cet attribut me sert pour stocker la réponse de la CA lorsque un client lui demande si un certificat est révoqué. 
        """
        self.cert = None
        self.response_ca = None
    
    def getResponseCa(self) -> Union[bool, None]:
        """
            Retourne la valeur de self.response_ca
            Returns:
                bool: True | False
                or
                None: Valeur d'origine.
        """
        
        return self.response_ca
    
    def setResponseCa(self, value: bool): 
        """
            Cette méthode permet d'insérer la réponse reçu de la part de la CA.

        Args:
            value (bool): True | False
        """
        if isinstance(value, bool):
            self.response_ca = value
    
    def insert_certificat(self, cert_: bytes) -> bool:
        """
            Cette méthode insère un certificat dans l'attribut 'cert' de la classe.

            Args:
                cert (bytes): le certificat à insérer

        """
        if isinstance(cert_, str):
            cert = cert_.encode()
        self.cert = cert
        return True if self.cert else False
    
    def get_certificate(self) -> Union[bytes, None]:
        """
            Cette méthode permet de renvoyer le certificat présent dans l'instance.

        Returns:
            (bytes): Le certificat.
            None: Si aucun certificat.
        """
        if self.cert is None:
            return None
        return self.cert
    
    def verify_certificat(self, cert: bytes, pubKey: RSAPublicKey) -> bool:
        """
            Cette méthode permet de vérifier la validité d'un certificat.

            Args:
                pubKey (RSAPublicKey): La clé publique de l'autorité de certification.

            Returns:
                bool: True si le certificat est valide et a été signé par la CA, False sinon.
        """
        try:
            # Charge le certificat au format PEM
            if not isinstance(cert, bytes):
                print("Le certificat n'est pas au format bytes")
                return False
            
            cert_obj = x509.load_pem_x509_certificate(cert, default_backend())

            # Vérifie la signature du certificat
            padding_algo = padding.PKCS1v15() 
            if cert_obj.signature_hash_algorithm is None:
                hash_algorithm = default_backend().hashalgorithm()  
            else:
                hash_algorithm = cert_obj.signature_hash_algorithm

            pubKey.verify(
                cert_obj.signature,
                cert_obj.tbs_certificate_bytes,
                padding_algo,
                hash_algorithm,
            )

            # Vérifie la date de validité du certificat
            current_time = datetime.now(timezone.utc)  # Assure que current_time est en UTC

            if cert_obj.not_valid_before_utc > current_time or cert_obj.not_valid_after_utc < current_time:
                print("Le certificat est invalide en raison de la date.")
                return False

            # Si la vérification réussit, le certificat est valide
            return True
        except Exception as e:
            # En cas d'erreur, le certificat est considéré comme invalide
            print(f"CERTIFICAT VERIFICATION : Erreur lors de la vérification du certificat :\n{e}")
            return False
