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
        print("VENDEUR : connexion à la file MQTT établie avec succès.")
        mqtt.subscribe(os.getenv("TOPIC_SUB_CLIENT"))
        mqtt.subscribe(os.getenv("TOPIC_SUB_CA"))

    else:
        print(f"Échec de la connexion à la file MQTT avec le code de retour {rc}")

def on_mqtt_message(client, userdata, message):
    """
        Logique à exécuter lorsqu'un message est reçu.
    """
    payload = message.payload.decode()
    
    # print(f"Message reçu sur le sujet {message.topic} : {payload}")
    print(f"Message reçu sur le sujet {message.topic}")
    message_data = json.loads(payload)
    
    # Message de la part de la CA
    if message.topic == os.getenv("TOPIC_SUB_CA"):
        if 'code' in message_data:
            from app import rsa_instance
            
            code = message_data['code']
            if code == 1: # Réception de la clé publique de la CA
                pubKeyCa = rsa_instance.receive_pub_key(message_data['data'])
                # Vérification si l'objet pubKeyCa est créé avec succès
                if pubKeyCa:
                    rsa_instance.insert_rsa_key(pubKeyCa, "ca")
                else:
                    print("Erreur lors de la désérialisation de la clé publique")
            
            elif code == 2: # Réception autre  
                print("TODO")
                
            else:
                # Code inconnu
                print("Code inconnu")
        else:
            # Code non trouvé dans le message
            print("Code non trouvé dans le message")
    
    # Message de la part du client
    elif message.topic == str(os.getenv("TOPIC_SUB_CLIENT")):
        if 'code' in message_data:
            from app import rsa_instance    # Import de l'instance rsa
            
            code = message_data['code']
            if code == 1: # Demande d'envoi de la clé publique du vendeur au client
                print(f"RECETION DEMANDE CLE DE LA PART DU CLIENT")
                pubKey = rsa_instance.get_my_pub_key_serialized()
                
                message = {
                    'code': 1,
                    'data': pubKey 
                }
                
                publish_message(os.getenv("TOPIC_PUBLISH_CLIENT"), json.dumps(message))
                print("TOPIC CLIENT : CLE PUBLIQUE ENVOYE.")
                
            elif code == 2: # Reception de la clé publique du client
                if rsa_instance.insert_rsa_key(rsa_instance.receive_pub_key(message_data['data']), "client") != 0:
                    print("SELLER: Error getting pubKey from client.")
                print("SELLER: CLE DU VENDEUR RECU")
                
            else:
                # Code inconnu
                print("Code inconnu")
        else:
            # Code non trouvé dans le message
            print("Code non trouvé dans le message")
    
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
        print(f"Error: ", e)
        return -1

# Enregistrez les routes MQTT sur le blueprint mqtt_bp
@mqtt_bp.route('/mqtt/test', methods=['GET'])
def mqtt_test():
    return 'Test MQTT', 200
