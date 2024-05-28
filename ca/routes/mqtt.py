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
        mqtt.subscribe(os.getenv("TOPIC_SUB_SELLER"))

    else:
        print(f"Échec de la connexion à la file MQTT avec le code de retour {rc}")

def on_mqtt_message(client, userdata, message):
    """
        Logique à exécuter lorsqu'un message est reçu.
    """
    from src.tools.tools import receive_exchange_secret_client 
    from app import rsa_instance, aes_instance 
    
    payload = message.payload.decode()
    
    # print(f"Message reçu sur le sujet {message.topic} : {payload}")
    print(f"Message reçu sur le sujet {message.topic}")

    # Convertir le payload en json
    message_data = json.loads(payload)

    # GESTION DES MESSAGES SUR LA TOPIC DU CLIENT
    if message.topic == str(os.getenv("TOPIC_SUB_CLIENT")):
        # Vérifie que la clé code est présente dans le message
        if 'code' in message_data:
            # Code de l'opération à traiter : 1, 2 ...
            code = message_data['code']
            
            if code == 1: # Envoi de la clé publique au client
                from app import rsa_instance
                pubKey = rsa_instance.get_my_pub_key_serialized()
                
                message = {
                    'code': 1,
                    'data': pubKey 
                }
                
                publish_message(os.getenv("TOPIC_PUBLISH_CLIENT"), json.dumps(message))
                print("TOPIC CLIENT : MESSAGE CODE 1 PUBLIE.")
            
            elif code == 2: # Échange du secret avec le client
                print(f"TOPIC CLIENT : Je recois une demande d'échange de secret.")
                error = receive_exchange_secret_client(rsa_instance, aes_instance, message_data['data'])
                if error == None:
                    print("ERROR SERVER: Erreur lors du décryptage.")
                    
                print("\nTOPIC CLIENT : SECRET RECU.")
            else:
                # Code inconnu
                print("Code inconnu")
        else:
            # Code non trouvé dans le message
            print("Code non trouvé dans le message")
    
    # GESTION DES MESSAGES SUR LA TOPIC DU VENDEUR   
    elif message.topic == str(os.getenv("TOPIC_SUB_SELLER")):
        code = message_data['code']
        
        if code == 1: # Envoi de la clé publique au vendeur
            from app import rsa_instance
            pubKey = rsa_instance.get_my_pub_key_serialized()
            if pubKey == None:
                print("ERROR PUBKEY")

            message = {
                'code': 1,
                'data': pubKey
            }
            
            publish_message(os.getenv("TOPIC_PUBLISH_SELLER"), json.dumps(message))
            print("TOPIC SELLER : MESSAGE CODE 1 PUBLIE.")
            
        elif code == 2: # Échange du secret avec le vendeur
            print(f"TOPIC CLIENT : Je recois une demande d'échange de secret.")
            error = receive_exchange_secret_client(rsa_instance, aes_instance, message_data['data'])
            if error == None:
                print("ERROR SERVER: Erreur lors du décryptage.")
                
            print("\nTOPIC CLIENT : SECRET RECU.")
        else:
            # Code inconnu
            print("Code inconnu")

def publish_message(topic, payload):
    """
        Publie un message sur un sujet MQTT donné.
        
        Args:
            topic (str): Le sujet sur lequel publier le message.
            payload (str): Le message à publier.
        
        Returns:
            str: Un message d'erreur en cas d'échec, None en cas de succès.
    """
    if not topic or not payload:
        return -1

    try:
        mqtt.publish(topic, payload)
        return None
    except Exception  as e:
        return e

# Enregistrez les routes MQTT sur le blueprint mqtt_bp
@mqtt_bp.route('/mqtt/test', methods=['GET'])
def mqtt_test():
    return 'Test MQTT', 200
