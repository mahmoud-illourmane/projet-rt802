from flask import Flask
from flask_cors import CORS

import paho.mqtt.client as mqtt
import threading

from routes.mqtt import start_mqtt_client

"""
|
|   Ce code constitue le point d'amorçage du serveur 
|   Flask qui gère la composante du vendeur
|
|   Auteur: Mahmoud ILLOURMANE
|   Date de création: 25 Mai 2024
|
"""

app = Flask(__name__)
CORS(app)

mqtt_client = mqtt.Client()

app.config['SERVEUR_CLIENT'] = 'http://127.0.0.1:5001'
app.config['SERVEUR_CA'] = 'http://127.0.0.1:5000'

# Importation du fichier api.py
from routes.api import *

if __name__ == '__main__':
    # Démarrage du client MQTT dans un thread séparé
    mqtt_thread = threading.Thread(target=start_mqtt_client)
    mqtt_thread.daemon = True
    mqtt_thread.start()
    
    # En Local
    app.run(port=5002, debug=True)
    