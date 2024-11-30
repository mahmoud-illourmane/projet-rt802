"""
|
|   Ce code constitue le point d'amorçage du serveur 
|   Flask qui gère la composante CA
|
|   Auteur: Mahmoud ILLOURMANE
|   Date de création: 27 Mars 2024
|
"""

from flask import Flask
from flask_cors import CORS

from dotenv import load_dotenv
import logging, os, sys, threading
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
from src.classes.certificat.certificat import Certificat

# Configuration des logs pour l'utilisation du Launcher.py
log_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'client.log')
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
certificat_instance = Certificat()

# Objet Event pour la synchronisation
code1_event = threading.Event()

def thread_code1():
    while True:
        # Attendre que l'événement soit déclenché
        code1_event.wait()
        # Affiche la clé publique lorsque l'événement est déclenché
        pubKey = f"Voici la clé publique depuis le thread : {rsa_instance.get_my_pub_key_pem()}"

        print("Voici la clé publique depuis le thread :")
        print(pubKey)
        # Réinitialisation de l'événement pour la prochaine utilisation
        code1_event.clear()

# Démarrer le thread
thread = threading.Thread(target=thread_code1)
thread.daemon = True
thread.start()

# Configure MQTT avec l'application Flask
configure_mqtt(app, code1_event)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
    