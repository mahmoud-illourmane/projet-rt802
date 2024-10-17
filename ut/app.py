from flask import Flask
from flask_cors import CORS

from dotenv import load_dotenv
import logging, os, sys
from pathlib import Path

# Ajoute les répertoires contenant les modules Python au chemin de recherche des modules
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

# Importation des modules personnel

# Fichiers de routes
from routes.api import api_bp

# Classes RSA AES & Certificat
from encryption.rsa import ChiffrementRSA
from encryption.aes import ChiffrementAES
from src.classes.certificat.certificat import Certificat

# Configuration des logs pour l'utilisation du Launcher.py
log_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'ut.log')
logging.basicConfig(filename=log_dir, level=logging.DEBUG)

# Instanciation du serveur Flask
app = Flask(__name__)
# Permet à vue.js d'intéragir avec Flask.
CORS(app, origins="*", methods=["GET", "POST", "OPTIONS"], allow_headers=["Content-Type", "Authorization"])

# Sauvegarde des Blueprints
app.register_blueprint(api_bp)

# Permet l'utilisation de os.getenv
load_dotenv()

app.config['MQTT_BROKER_URL'] = os.getenv("MQTT_BROKER_URL")
app.config['MQTT_BROKER_PORT'] = 1883
app.config['MQTT_REFRESH_TIME'] = os.getenv("MQTT_REFRESH_TIME") 
    
# Instanciation des classes RSA et AES
rsa_instance = ChiffrementRSA()
aes_instance = ChiffrementAES()
certificat_instance = Certificat()

"""
|
|   Ce code constitue le point d'amorçage du serveur 
|   Flask qui gère la composante du UT.
|
|   Auteur: Mahmoud ILLOURMANE
|   Date de création: 17 Oct. 2024
|
"""

if __name__ == '__main__':
    app.run(port=5005, debug=True)
    