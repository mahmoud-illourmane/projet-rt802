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
        print(f"VENDEUR : Échec de la connexion à la file MQTT avec le code de retour {rc}")

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
            from app import rsa_instance, aes_instance, certificat_instance
            
            code = message_data['code']
            if code == 1: # Réception de la clé publique de la CA
                print("TOPIC CA CODE 1 : RECEPTION DE LA CLE PUBLIQUE DE LA CA")
                pubKeyCa = rsa_instance.receive_pub_key_pem(message_data['data'])
                # Vérification si l'objet pubKeyCa est créé avec succès
                if pubKeyCa:
                    rsa_instance.insert_pub_key(pubKeyCa, "ca")
                else:
                    print("Erreur lors de la désérialisation de la clé publique")
                
                print("TOPIC CA CODE 1 : CLE AJOUTE AU DICTIONNAIRE DES CLES")
                
            elif code == 2: # Réception d'un certificat de la part de la CA.  
                print("TOPIC CA CODE 2 : RECEPTION DU CERTIFICAT SIGNE DE LA PART DE LA CA")
                # Récupération de la liste des certificats
                certificates = message_data['data']
                
                certificat_valide_crypted = certificates.get("certif_valide")
                certificat_expired_crypted = certificates.get("certif_expired")
                certificat_revoked_crypted = certificates.get("certif_revoked")
                
                # Récuperation de la clé AES depuis l'instance 
                aesKey = aes_instance.get_aes_key("ca")
                if aesKey is None:
                    print("Erreur récupération de la clé AES pour décrypter les certificats reçu.")
                    return None
                
                certificat_valide = aes_instance.decrypt(certificat_valide_crypted, aesKey, True)
                certificat_expired = aes_instance.decrypt(certificat_expired_crypted, aesKey, True)
                certificat_revoked = aes_instance.decrypt(certificat_revoked_crypted, aesKey, True)
                if certificat_valide is None or certificat_expired is None or certificat_revoked is None:
                    print("Erreur décryptage des certificats.")
                    return None
                
                insered = certificat_instance.insert_certificat(certificat_valide, "Certificat Valide", False)
                if insered == False:
                    print("VENDEUR: ERREUR lors de l'insertion du certificat dans le dictionnaire des certificats.")
                    return None
                    
                insered = certificat_instance.insert_certificat(certificat_expired, "Certificat Expired", False)
                if insered == False:
                    print("VENDEUR: ERREUR lors de l'insertion du certificat dans le dictionnaire des certificats.")
                    return None
                
                insered = certificat_instance.insert_certificat(certificat_revoked, "Certificat Revoked", True)
                if insered == False:
                    print("VENDEUR: ERREUR lors de l'insertion du certificat dans le dictionnaire des certificats.")
                    return None
                
                print("TOPIC CA CODE 2 : CERTIFICATS INSERES")
            else:
                # Code inconnu
                print("Code inconnu")
        else:
            # Code non trouvé dans le message
            print("Code non trouvé dans le message")
    
    # Message de la part du client
    elif message.topic == str(os.getenv("TOPIC_SUB_CLIENT")):
        if 'code' in message_data:
            from app import rsa_instance, aes_instance, certificat_instance
            code = message_data['code']
            
            if code == 1: # Demande d'envoi de la clé publique du vendeur au client
                print(f"RECETION DEMANDE CLE DE LA PART DU CLIENT")
                pubKey = rsa_instance.get_my_pub_key_pem()
                
                message = {
                    'code': 1,
                    'data': pubKey 
                }
                
                publish_message(os.getenv("TOPIC_PUBLISH_CLIENT"), json.dumps(message))
                print("TOPIC CLIENT : CLE PUBLIQUE ENVOYE.")
                
            elif code == 2: # Reception de la clé publique du client
                clientPubKeyBytes = rsa_instance.receive_pub_key_pem(message_data['data'])
                if clientPubKeyBytes is not None:
                    rsa_instance.insert_pub_key(clientPubKeyBytes, "client")
                    print("SELLER: CLE DU VENDEUR RECU")
                else:
                    print("ERROR SELLER: JE RECOIS UNE CLE NONE CODE 2 TOPIC SUB CLIENT.")
            
            elif code == 3: # Échange du secret avec le client
                from ca.src.tools.tools import receive_exchange_secret
                
                print(f"TOPIC VENDEUR : Je recois une demande d'échange de secret de la part du client.")
                aes_key_encrypted_by_rsa_base64 = message_data['data']

                receive_exchange_secret(rsa_instance, aes_instance, aes_key_encrypted_by_rsa_base64, "client")  
                print("\nTOPIC VENDEUR : SECRET RECU DE LA PART DU CLIENT.")
            
            elif code == 4: # Envoi de la clé publique au client
                print("RECU DEMANDE D'ENVOI DU CERTIFICAT.")
                cert = certificat_instance.get_certificate_to_send()
                if cert is None:
                    print("Aucun certificat n'a été mis dans 'certificat_to_send'")
                    return
                cert_encode = cert.decode('utf-8')
                
                message = {
                    'code': 3,
                    'data': cert_encode
                }
                
                publish_message(os.getenv("TOPIC_PUBLISH_CLIENT"), json.dumps(message))
                print("TOPIC CLIENT : CERTIFICAT ENVOYEE.")
                
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
        return "Invalid topic or payload"

    try:
        mqtt.publish(topic, payload)
        return None
    except Exception as e:
        print(f"ERROR PUBLISH:\n {e}")
        return f"Failed to publish message: {e}"

# Route de test non utilisée
@mqtt_bp.route('/mqtt/test', methods=['GET'])
def mqtt_test():
    return 'Test MQTT', 200
