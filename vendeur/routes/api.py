from flask import jsonify, request
from flask import Blueprint

import sys, os, requests, json
import asyncio

api_bp = Blueprint('api', __name__)

# Ajoute le chemin du dossier parent à sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import en relation avec la file MQTT
from .mqtt import publish_message

# from tools.tools import write_log
from encryption.rsa import ChiffrementRSA
from encryption.aes import ChiffrementAES

@api_bp.route('/seller/api/hello', methods=['GET'])
def hello():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    available = {
        'bool': "True"
    }
    return jsonify(available), 200
    
#
#   INTERNAL OPERATIONS
#

@api_bp.route('/seller/api/generate-rsa-key', methods=['GET'])
def generateRSAKey():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    from app import rsa_instance
    
    check_rsa = rsa_instance.get_my_pub_key()
    if not check_rsa:
        rsa_instance.generate_keys()
        return jsonify({'message': "Clés générés avec succès."}), 200
    else:
        return jsonify({'message': "Des clés RSA existent déjà sur le vendeur."}), 200
    
@api_bp.route('/seller/api/generate-aes-key', methods=['GET'])
def generateAESKey():
    """
        Cette route sert à créer des clés AES pour les utiliser
        soit avec le CA soit pour le client.
        
        Args:
            name (str): Un identifiant pour catégoriser la clé AES ['ca', 'client']
        Returns:
            json: response
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import aes_instance
    
    # Le nom de l'identifiant pour qui générer une clé AES.
    name = request.args.get('name')
    if name not in ['ca', 'client']:
        return jsonify({'message': f"ERROR: Unknown name '{name}' identifier."}), 200
    
    # Je vérifie que la clé n'existe pas déjà.
    check_aes = aes_instance.aes_key_exist(name)
    if check_aes:
        return jsonify({'message': f"La Clé AES à utiliser avec '{name}' est déjà présente."}), 200
    else:
        new_key = aes_instance.generate_key()
        aes_instance.insert_aes_key(new_key, name)
        return jsonify({'message': f"La clé AES à utiliser avec '{name}' a été générée."}), 200
    
#
#   VERIFY INTERNAL KEYS
#

@api_bp.route('/seller/api/check-rsa-key', methods=['GET'])
def checkRSAKey():
    """
        Cette route vérifie que le vendeur dispose de sa paire de
        clé RSA.
        
        Returns:
            json: reponse
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405    
    from app import rsa_instance
    
    check_rsa = rsa_instance.get_my_pub_key()
    
    if check_rsa:
        return jsonify({'message': "Clés RSA présentes."}), 200
    else:
        return jsonify({'message': "Aucune paire de clés RSA trouvée."}), 200

@api_bp.route('/seller/api/check-aes-key', methods=['GET'])
def checkAESKey():
    """
        Cette route permet de vérifier que le vendeur a généré
        les clés à utiliser avec la CA et le Client.
        
        Returns:
            json: response
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import aes_instance
    
    name = request.args.get('name')
    if name not in ['ca', 'client']:
        return jsonify({'message': "ERROR: Unknown name identifier."}), 200
    
    check_aes = aes_instance.aes_key_exist(name)
    if check_aes:
        return jsonify({'message': f"La Clé AES à utiliser avec '{name}' est présente."}), 200
    else:
        return jsonify({'message': f"Aucune clé AES n'a été trouvée pour le domaine '{name}'."}), 200

#   START
#   Opérations externes au vendeur
#

#   == OPERATION WITH ==
#
#   ======== CA ========
#
#   ====================

#
#   GET PUB KEYS
#

@api_bp.route('/seller/api/get-pub-key-ca', methods=['GET'])
def get_ca_pub_key():
    """
        Cette route publie sur la topic de la CA, pour 
        récuperer sa clé publique.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405

    message = {
        'code' : 1,
        'data' : None
    }
    
    publish_message(os.getenv("TOPIC_PUBLISH_CA"), json.dumps(message))
    print("VENDEUR : Demande clé publique à la CA sur MQTT.")
    
    return jsonify({'message': "ok"}), 200

@api_bp.route('/seller/api/print-pub-key-ca', methods=['GET'])
async def printPubKeyCa():
    """
        Cette route sert juste à afficher la clé publique de la CA
        sur la vue.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import rsa_instance

    await asyncio.sleep(1)  # Attend une seconde pour être sur que la clé est bien stocké dans la classe.
    caPubKey = rsa_instance.get_pub_key("ca", True)
    
    if not caPubKey:
        return jsonify({'message': "VENDEUR : Vous n'avez pas la clé publique de la CA."}), 200
    elif caPubKey == -1:
        return jsonify({'message': "VENDEUR : Erreur lors de l'extraction de la clé publique de la CA."}), 200
    
    return jsonify({'message': caPubKey}), 200

@api_bp.route('/seller/api/get-pub-key-client', methods=['GET'])
def getPubKeyClient():
    """
        Cette route permet de publier la demande d'envoi 
        de la clé publique du client.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    print("MQTT : Demande clé publique au client.")
    message = {
        'code' : 2,
        'data' : None
    }
    
    error = publish_message(os.getenv("TOPIC_PUBLISH_CLIENT"), json.dumps(message))
    if error == -1:
        print("Error publish to topic client.")
        return jsonify({'message': "Error publish to topic client."}), 200
    
    return jsonify({'message': "ok"}), 200

@api_bp.route('/seller/api/print-pub-key-client', methods=['GET'])
async def printPubKeyClient():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import rsa_instance
    
    await asyncio.sleep(1)
    
    caPubKey = rsa_instance.get_pub_key("client", True)
    if caPubKey == -1:
        return jsonify({'message': "SELLER: ERROR SERVER."}), 500

    message = {
        'code' : 1,
        'data' : caPubKey
    }

    return jsonify({'message': message}), 200

#
#   SECRET EXCHANGE CA
#

@api_bp.route('/seller/api/secret-exchange-ca', methods=['GET'])
async def secretExchangeCa():
    """
        Cette route, permet d'entamer le processus d'échange
        de secret entre le vendeur et la CA. Il publie la 
        demande sur la file MQTT.
        
        Le client a besoin d'avoir :
            - De sa clé publique AES.
            - De la clé publique de la CA.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import rsa_instance, aes_instance
 
    # Je récupère la clé publique de la CA depuis l'instance du vendeur.
    caPubKey = rsa_instance.get_pub_key("ca")
    if caPubKey is None:
        return jsonify({'message': "ERROR: La clé publique de la CA est introuvable."}), 200
    
    # Je récupère la clé AES du vendeur.
    aesKey = aes_instance.get_aes_key("ca")
    if aesKey == None:
        return jsonify({'message': "ERROR: La clé AES utilise pour les échanges avec la CA est introuvable."}), 200
        
    # Je crypte la clé AES par la clé publique de la CA en base64.
    aes_cipher_base64 = rsa_instance.crypter(aesKey, caPubKey, True)
    if aes_cipher_base64 == None:
        return jsonify({'message': "ERROR SERVER: La clé AES du client n'a pas pu être chiffrée."}), 200
    
    # Je construit le message à publier sur la file MQTT.
    message = {
        'code' : 2,
        'data' : aes_cipher_base64
    }
    
    # Je publie le message.
    error = publish_message(os.getenv("TOPIC_PUBLISH_CA"), json.dumps(message))
    if error:
        return jsonify({'message': "ERROR SERVEUR: publication sur la file MQTT impossible."}), 200
    
    return jsonify({'message': "Le secrêt vient d'être publié sur la file MQTT."}), 200

@api_bp.route('/seller/api/request-certificat', methods=['POST'])
def requestCertificat():
    """
        Cette route permet de publier sur la file MQTT une demande
        de création de certificat par la CA.
    """
    if request.method != 'POST':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import rsa_instance, aes_instance
    
    # Récuperation de la clé AES de communication entre le vendeur et la CA.
    aesKey = aes_instance.get_aes_key("ca")
    if aesKey is None:
        return jsonify({'message': "ERROR: La clé AES de communication avec CA est introuvable."}), 200

    # Les informations du vendeur reçu depuis le formulaire.
    dataReceived = request.get_json()   
    if dataReceived is None:
        return jsonify({'message': "ERROR: Aucun données reçu pour faire la demande de certificat."}), 200
    # Conversion en json
    try:
        dataReceivedJson = json.dumps(dataReceived)
    except Exception as e:
        return jsonify({'message': f"ERROR: Impossible de convertir les données reçues en JSON: {e}"}), 200
    
    # Convertion dataReceivedJson en bytes pour le chiffrement AES
    dataReceivedBytes = dataReceivedJson.encode('utf-8')
    encryptedDataUser = aes_instance.encrypt(dataReceivedBytes, aesKey, True)
    if encryptedDataUser is None:
        return jsonify({'message': "ERROR SERVEUR: Erreur lors de la tentative de cryptage des données à inclure dans le certificat (requestCertificat)."}), 200

    # Récuperation de la clé publique du vendeur pour la crypter
    pubKey = rsa_instance.get_my_pub_key_pem()
    if pubKey is None:
        return jsonify({'message': 'Clé publique non trouvée.'}), 200
    
    # Cryptage de la clé publique avec la clé AES
    pubKeyBytes = pubKey.encode('utf-8')
    encryptedPubKey = aes_instance.encrypt(pubKeyBytes, aesKey, True)
    if encryptedPubKey is None:
        return jsonify({'message': "ERROR SERVEUR: Erreur lors de la tentative de cryptage de la clé publique (requestCertificat)."}), 200
    
    # Préparation des données à envoyer
    dataToSend = {
        'code': 3,
        'dataUser': encryptedDataUser,
        'pubKey': encryptedPubKey
    }
    
    try:
        jsonDataToSend = json.dumps(dataToSend)
    except Exception as e:
        return jsonify({'message': f"ERROR: Impossible de convertir les données à envoyer en JSON: {e}"}), 200
    
    # Je publie le message
    error = publish_message(os.getenv("TOPIC_PUBLISH_CA"), jsonDataToSend)
    if error:
        return jsonify({'message': f"ERROR SERVEUR: publication sur la file MQTT impossible (requestCertificat): {error}"}), 200
    
    print("DEMANDE DE CERTIFICAT ENVOYÉE")
    return jsonify({'message': 'Demande de certificat envoyée.'}), 200
