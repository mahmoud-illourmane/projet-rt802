import json
import requests

from config import *
from encryption.rsa import ChiffrementRSA

class Certificat:
    def __init__(self):
        self.ca = CA_ADDRESS
        self.certificate_data = {}
    
    def collect_entries(self):
        """
            Cette méthode sert à récuperer les entrés de l'utilisateur
            dans une liste
        """
        common_name = input("Nom commun (CN) : ")
        organization = input("Organisation (O) : ")
        country = input("Pays (C) : ")
        
        # Récupération de la clé publique du client
        rsa_client = ChiffrementRSA()
        pub_key = rsa_client.charger_cle_publique()
        
        # Exporter la clé publique au format PEM pour l'envoyer dans le json
        pub_key_pem = pub_key.export_key().decode()
   
        self.certificate_data = {
            "common_name": common_name,
            "organization": organization,
            "country": country,
            "public_key": pub_key_pem
        }
    
    def send_certificat_data(self):
        """
            Cette fonction envoi les données json saisie par 
            l'utilisateur à CA pour la création d'un certificat.
            Les données envoyés :
                - Les donnés saisie par l'utilisateur ;
                - La clé publique de l'utilisateur ;
        """
        # L'adresse de la CA
        url = self.ca + CA_CREATE_CERTIFICAT
        
        # Récupération des données saisies par le client
        self.collect_entries()
            
        try:
            response = requests.post(url, json=self.certificate_data)
            if response.status_code == 200:
                print(f"Les entrées ont été envoyées avec succès à l'adresse à CA")
            else:
                print(f"Erreur lors de l'envoi des entrées à CA")
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de l'envoi des entrées : {str(e)}")