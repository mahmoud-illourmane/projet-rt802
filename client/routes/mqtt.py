from flask import current_app
from flask_mqtt import Mqtt
from flask import Blueprint
import os, json, struct

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
        print(f"CLIENT :  Échec de la connexion à la file MQTT avec le code de retour:\n{rc}")

def on_mqtt_message(client, userdata, message):
    """
        Logique à exécuter lorsqu'un message est reçu.
    """
    payload = message.payload.decode()
    
    # print(f"Message reçu sur le sujet {message.topic} : {payload}")
    print(f"Message reçu sur le sujet {message.topic}")
    message_data = json.loads(payload)
    
    # MESSAGE DE LA PART DE LA CA
    if message.topic == str(os.getenv("TOPIC_SUB_CA")):
        if 'code' in message_data:
            from app import rsa_instance, aes_instance, certificat_instance
            
            code = message_data['code'] # Code de l'opération reçu
            
            if code == 1: # Réception de la clé publique de la CA
                # Appel de la méthode didié pour transformer la clé reçu au bon format
                pubKeyCa = rsa_instance.receive_pub_key_pem(message_data['data'])
                # Vérification si l'objet pubKeyCa est créé avec succès
                if pubKeyCa:
                    rsa_instance.insert_pub_key(pubKeyCa, "ca")
                else:
                    print("Erreur lors de la désérialisation de la clé publique.")
                    
            elif code == 2: # Réception d'une réponse pour indiquer si un certificat a été révoqué
                print("TOPIC CA CODE 2 : RECEPTION D'UNE REPONSE DE CERTIFICAT REVOQUE OU NON.")
                encrypted_result = message_data['data']
                
                # Récupération de la clé AES de communication avec la CA
                aesKeyCa = aes_instance.get_aes_key("ca")
                if aesKeyCa is None:
                    print("TOPIC CA CODE 2 : Clé aes de communication avec la CA introuvable.")
                    return None
                byte_result = aes_instance.decrypt(encrypted_result, aesKeyCa, True)
                if byte_result is None:
                    return None
                bool_result =  struct.unpack('?', byte_result)[0]
                
                # Je place la réponse de la CA dans la classe certificat
                certificat_instance.setResponseCa(bool_result)
                print("\n\n\nCERTIFICAT REVOQUE ? ", bool_result)
                
            else:
                # Code inconnu
                print("Code inconnu")
        else:
            # Code non trouvé dans le message
            print("Code non trouvé dans le message")
    
    # MESSAGE DE LA PART DU VENDEUR
    elif message.topic == str(os.getenv("TOPIC_SUB_SELLER")):
        if 'code' in message_data:
            from app import rsa_instance
            
            code = message_data['code']
            if code == 1: # Réception de la clé publique du vendeur
                sellerPubKey = rsa_instance.receive_pub_key_pem(message_data['data'])
                if sellerPubKey is not None:
                    rsa_instance.insert_pub_key(sellerPubKey, "seller")
                    print("CLIENT: CLE DU VENDEUR RECU")
                
            elif code == 2: # Envoi de la clé publique du client au vendeur
                print(f"RECETION DEMANDE DE CLE DE LA PART DU VENDEUR")
                pubKey = rsa_instance.get_my_pub_key_pem()
                
                message = {
                    'code': 2,
                    'data': pubKey 
                }
                
                publish_message(os.getenv("TOPIC_PUBLISH_SELLER"), json.dumps(message))
                print("TOPIC CLIENT : CLE PUBLIQUE ENVOYE AU VENDEUR.")
            
            elif code == 3: # Réception d'un certificat
                from app import certificat_instance
                
                print("TOPIC CLIENT : RECEPTION D'UN CERTIFICAT")
                                
                cert = message_data['data']
                # Insertion du certificat dans la classe pour pouvoir afficher sur la vue.
                error = certificat_instance.insert_certificat(cert)
                if error == False:
                    print("ERROR INSERTION DU CERTIFICAT DANS LA CLASSE.")
                    return None
                    
                print("TOPIC CLIENT : LE CERTIFICAT A BIEN ETE INSERER DANS LA CLASSE DE CERTIFICAT.")
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
   
# Routes MQTT sur le blueprint mqtt_bp
@mqtt_bp.route('/mqtt/test', methods=['GET'])
def mqtt_test():
    return 'Test MQTT', 200
