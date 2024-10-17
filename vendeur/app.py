from flask import Flask
from flask_cors import CORS

from dotenv import load_dotenv
import logging, os, sys
from pathlib import Path

# Ajoute les répertoires contenant les modules Python au chemin de recherche des modules
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

# Importation des modules personnel
from routes.mqtt import configure_mqtt

# Fichiers de routes
from routes.api import api_bp
from routes.mqtt import mqtt_bp

# Classes RSA AES & Certificat
from encryption.rsa import ChiffrementRSA
from encryption.aes import ChiffrementAES
from src.classes.certificat.certificat import Certificat_vendeur

# Configuration des logs pour l'utilisation du Launcher.py
log_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'vendeur.log')
logging.basicConfig(filename=log_dir, level=logging.DEBUG)

# Instanciation du serveur Flask
app = Flask(__name__)
CORS(app)   # Permet à vue.js d'intéragir avec Flask.

# Sauvegarde des Blueprints
app.register_blueprint(api_bp)
app.register_blueprint(mqtt_bp, url_prefix='/mqtt')

# Permet l'utilisation de os.getenv
load_dotenv()

app.config['MQTT_BROKER_URL'] = os.getenv("MQTT_BROKER_URL")
app.config['MQTT_BROKER_PORT'] = 1883
app.config['MQTT_REFRESH_TIME'] = os.getenv("MQTT_REFRESH_TIME") 
    
# Instanciation des classes RSA et AES
rsa_instance = ChiffrementRSA()
aes_instance = ChiffrementAES()
certificat_instance = Certificat_vendeur()

"""
|
|   Ce code constitue le point d'amorçage du serveur 
|   Flask qui gère la composante du vendeur
|
|   Auteur: Mahmoud ILLOURMANE
|   Date de création: 25 Mai 2024
|
"""

# Configurer MQTT avec l'application Flask
configure_mqtt(app)

if __name__ == '__main__':
    app.run(port=5002, debug=True)
    