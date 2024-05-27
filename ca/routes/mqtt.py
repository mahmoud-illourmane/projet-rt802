from flask import current_app
from flask_mqtt import Mqtt
from flask import Blueprint

import os, json

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
    
    # print(f"Message reçu sur le sujet {message.topic} : {payload}")
    print(f"Message reçu sur le sujet {message.topic}")

    # Convertir le payload en json
    message_data = json.loads(payload)

    if message.topic == str(os.getenv("TOPIC_SUB_CLIENT")):
        # Vérifie que la clé code est présente dans le message
        if 'code' in message_data:
            from app import rsa_instance, aes_instance
            
            code = message_data['code']
            if code == 1: # Envoi de la clé publique au client
                pubKey = rsa_instance.get_my_pub_key_serialized()
                
                message = {
                    'code': 1,
                    'data': pubKey 
                }
                publish_message(os.getenv("TOPIC_PUBLISH_CLIENT"), json.dumps(message))
                print("TOPIC CLIENT : MESSAGE CODE 1 PUBLIE.")
            
            elif code == 2: # Échange du secret avec le client
                print(f"Je recois une demande de secret.")
                
                # J'enlève le base64
                rsa_cipher = rsa_instance.decrypt_cipher_base64(message_data['data'])
                decrypted_aes_key = rsa_instance.decrypter(rsa_cipher)
                
                print(decrypted_aes_key)
                aes_instance.insert_aes(decrypted_aes_key, "client")
                
                print("\nTOPIC CLIENT : SECRET RECU.")
            else:
                # Code inconnu
                print("Code inconnu")
        else:
            # Code non trouvé dans le message
            print("Code non trouvé dans le message")
            
    elif message.topic == str(os.getenv("TOPIC_SUB_SELLER")):
        code = message_data['code']
        if code == 1: 
            print("Action pour le code 1")
        elif code == 2:
            print("Action pour le code 2")
        else:
            # Code inconnu
            print("Code inconnu")

def publish_message(topic, payload):
    """
        Publie un message sur un sujet MQTT donné.
    """
    mqtt.publish(topic, payload)

# Enregistrez les routes MQTT sur le blueprint mqtt_bp
@mqtt_bp.route('/mqtt/test', methods=['GET'])
def mqtt_test():
    return 'Test MQTT', 200
