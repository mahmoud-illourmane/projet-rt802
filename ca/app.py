from flask import Flask
from flask_cors import CORS

import paho.mqtt.client as mqtt
import threading

from routes.mqtt import start_mqtt_client

"""
|
|   Ce code constitue le point d'amorçage du serveur 
|   Flask qui gère la composante CA
|
|   Auteur: Mahmoud ILLOURMANE
|   Date de création: 27 Mars 2024
|
"""

app = Flask(__name__)
CORS(app)

mqtt_client = mqtt.Client()

# Activation du mode de débogage
app.debug = True                                                                

app.config['SERVEUR_CLIENT'] = 'http://127.0.0.1:5001'
app.config['SERVEUR_VENDEUR'] = 'http://127.0.0.1:5002'

# Importation du fichier api.py
from routes.api import *

if __name__ == '__main__':
    # Démarrage du client MQTT dans un thread séparé
    mqtt_thread = threading.Thread(target=start_mqtt_client)
    mqtt_thread.daemon = True
    mqtt_thread.start()
    
    # En Local
    app.run(host='0.0.0.0', port=5000)