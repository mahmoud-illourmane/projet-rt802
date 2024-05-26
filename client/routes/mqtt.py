from flask import current_app
from flask_mqtt import Mqtt
from flask import Blueprint

import os, json
import asyncio

from encryption.rsa import ChiffrementRSA

mqtt_bp = Blueprint('mqtt', __name__)

mqtt = Mqtt()

def configure_mqtt(app):
    """
        Configure les paramètres MQTT et lie les callbacks.
    """
    
    mqtt.init_app(app)
    
    @mqtt.on_connect()
    def handle_connect(client, userdata, flags, rc):    
        on_mqtt_connect(client, userdata, flags, rc)
        
    @mqtt.on_message()
    def handle_mqtt_message(client, userdata, message):
        on_mqtt_message(client, userdata, message)

def on_mqtt_connect(client, userdata, flags, rc):
    """
        Logique à exécuter lors de la connexion à la file MQTT.
    """
    if rc == 0:
        print("CLIENT : connexion à la file MQTT établie avec succès.")
        mqtt.subscribe(os.getenv("TOPIC_SUB_CA"))
        mqtt.subscribe(os.getenv("TOPIC_SUB_SELLER"))
    else:
        print(f"Échec de la connexion à la file MQTT avec le code de retour {rc}")

def on_mqtt_message(client, userdata, message):
    """
        Logique à exécuter lorsqu'un message est reçu.
    """
    payload = message.payload.decode()
    
    print(f"Message reçu sur le sujet {message.topic} : {payload}")
    message_data = json.loads(payload)
    
    if message.topic == str(os.getenv("TOPIC_SUB_CA")):
        if 'code' in message_data:
            rsaInstance = ChiffrementRSA()
            code = message_data['code']
            if code == 1: # Réception de la clé publique de la CA
                if rsaInstance.ecrire_pub_key_ca(message_data['data']) != 0:
                    print("CLIENT: Error getting pubKey from CA")
                    
            elif code == 2: # Réception de la clé publique du vendeur
                if rsaInstance.ecrire_pub_key_seller(message_data['data']) != 0:
                    print("CLIENT: Error getting pubKey from SELLER")
            else:
                # Code inconnu
                print("Code inconnu")
        else:
            # Code non trouvé dans le message
            print("Code non trouvé dans le message")
    
    elif message.topic == str(os.getenv("TOPIC_SUB_SELLER")):
        if 'code' in message_data:
            rsaInstance = ChiffrementRSA()
            code = message_data['code']
            if code == 1: # Réception de la clé publique du vendeur
                if rsaInstance.ecrire_pub_key_seller(message_data['data']) != 0:
                    print("CLIENT: Error getting pubKey from SELLER")
                    
            elif code == 1: 
                print("Action pour le code 2")
            else:
                # Code inconnu
                print("Code inconnu")
        else:
            # Code non trouvé dans le message
            print("Code non trouvé dans le message")
        

def publish_message(topic, payload):
    """
        Publie un message sur un sujet MQTT donné.
    """
    mqtt.publish(topic, payload)

# Routes MQTT sur le blueprint mqtt_bp
@mqtt_bp.route('/mqtt/test', methods=['GET'])
def mqtt_test():
    return 'Test MQTT', 200
