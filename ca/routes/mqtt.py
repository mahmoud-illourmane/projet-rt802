from flask import current_app
from flask_mqtt import Mqtt
from flask import Blueprint

import os, json

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
        print("CA : connexion à la file MQTT établie avec succès.")
        mqtt.subscribe(os.getenv("TOPIC_SUB_CLIENT"))

    else:
        print(f"Échec de la connexion à la file MQTT avec le code de retour {rc}")

def on_mqtt_message(client, userdata, message):
    """
    Logique à exécuter lorsqu'un message est reçu.
    """
    payload = message.payload.decode()
    print(f"Message reçu sur le sujet {message.topic} : {payload}")

    # Convertir le payload en un dictionnaire Python
    message_data = json.loads(payload)

    # Vérifier le code et exécuter des actions en conséquence
    if 'code' in message_data:
        code = message_data['code']
        if code == 1: # Envoi de la clé publique au client
            rsaInstance = ChiffrementRSA()
            pubKey = rsaInstance.exporter_cle_publique_pem()
            
            message = {
                'code': 1,
                'data': pubKey 
            }
            publish_message(os.getenv("TOPIC_PUBLISH_CLIENT"), json.dumps(message))
            print("MESSAGE PUBLIER.")
        elif code == 2:
            
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

# Enregistrez les routes MQTT sur le blueprint mqtt_bp
@mqtt_bp.route('/mqtt/test', methods=['GET'])
def mqtt_test():
    return 'Test MQTT', 200
