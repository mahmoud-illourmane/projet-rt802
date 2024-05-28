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
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    from app import aes_instance
    
    check_aes = aes_instance.get_my_aes_key()
    if not check_aes:
        if aes_instance.generate_key() == -1:
            return jsonify({'error': "Erreur serveur."}), 500
        else:
            return jsonify({'message': "Clé AES générée avec succès."}), 200
    else:
        return jsonify({'message': "Une clé AES existe déjà sur le vendeur."}), 200

#
#   VERIFY INTERNAL KEYS
#

@api_bp.route('/seller/api/check-rsa-key', methods=['GET'])
def checkRSAKey():
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
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import aes_instance
    
    check_aes = aes_instance.get_my_aes_key()
    if check_aes:
        return jsonify({'message': "Clé AES présente."}), 200
    else:
        return jsonify({'message': "Aucune clé AES trouvée."}), 200
  


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
    sellerAesKey = aes_instance.get_my_aes_key()
    print("\n\nMY AES KEY ORININAL:\n", sellerAesKey)
    if sellerAesKey == None:
        return jsonify({'message': "ERROR: La clé AES du vendeur est introuvable."}), 200
        
    # Je crypte la clé AES du vendeur par la clé publique de la CA et convertir en base64.
    aes_cipher_base64 = rsa_instance.crypter(sellerAesKey, caPubKey, True)
    if aes_cipher_base64 == None:
        print("ERROR: La clé AES du vendeur n'a pas pu être crypté ou converti en base64 route('secretExchangeCa').")
        return jsonify({'message': "ERROR: La clé AES du vendeur n'a pas pu être crypté ou converti en base64 route('secretExchangeCa')."}), 200
    
    # Je construit le message à publier sur la file MQTT.
    message = {
        'code' : 2,
        'data' : aes_cipher_base64
    }
    
    print("\n\nAES SENDED: ", aes_cipher_base64)
    
    # Je publie le message.
    error = publish_message(os.getenv("TOPIC_PUBLISH_CA"), json.dumps(message))
    if error:
        return jsonify({'message': "ERROR SERVEUR: publication sur la file MQTT impossible."}), 200
    
    return jsonify({'message': "Le secrêt vient d'être publié sur la file MQTT."}), 200

@api_bp.route('/seller/api/request-certificat', methods=['POST'])
def requestCertificat():
    if request.method != 'POST':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import rsa_instance, aes_instance
    
    # Informations à inclure dans le certificat
    dataReceived = json.dumps(request.get_json())
    # Cryptage des données à inclure dans le certificat
    encryptedDataUser = aes_instance.encrypt(dataReceived.encode('utf-8'), True)
    if encryptedDataUser == None:
        return jsonify({'message': "ERROR SERVEUR: Erreur lors de la tentative de cryptage de la clé publique (requestCertificat)."}), 200

    # Récuperation de la clé publique du vendeur
    pubKey = rsa_instance.get_my_pub_key_pem()
    if pubKey == None:
        return jsonify({'message': 'Clé publique non trouvée.'}), 200
    
    # Cryptage de la clé publique avec la clé AES
    # Je dois convertir cette clé en bytes encode('utf-8')
    encryptedPubKey = aes_instance.encrypt(pubKey.encode('utf-8'), True)
    if encryptedPubKey == None:
        return jsonify({'message': "ERROR SERVEUR: Erreur lors de la tentative de cryptage de la clé publique (requestCertificat)."}), 200
    
    # Préparation des données à envoyer
    dataToSend = {
        'code': 3,
        'dataUser': encryptedDataUser,
        'pubKey': encryptedPubKey
    }
        
    # Je publie le message.
    error = publish_message(os.getenv("TOPIC_PUBLISH_CA"), json.dumps(dataToSend))
    if error:
        return jsonify({'message': "ERROR SERVEUR: publication sur la file MQTT impossible (requestCertificat)."}), 200
    print("DEMANDE ENVOYE")
    
    return jsonify({'message': 'Demande de certificat envoyée.'}), 200