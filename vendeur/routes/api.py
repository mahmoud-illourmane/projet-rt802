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
        if rsa_instance.generer_cles() == -1:
            return jsonify({'error': "Erreur serveur."}), 500
        else:
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
    caPubKey = rsa_instance.get_rsa_key("ca", True)
    
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
    
    caPubKey = rsa_instance.get_rsa_key("client", True)
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

    # Je récupère la clé publique de la CA depuis l'instance RSA du vendeur.
    caPubKey = rsa_instance.get_rsa_key("ca")
    if caPubKey == None:
        return jsonify({'message': "ERROR SERVER: La clé publique de la CA est introuvable."}), 200
    
    # Je récupère la clé AES du vendeur depuis l'instance AES du vendeur.
    sellerAesKey = aes_instance.get_my_aes_key()
    if sellerAesKey == None:
        return jsonify({'message': "ERROR SERVER: La clé AES du vendeur est introuvable."}), 200
    
    # Je crypte la clé AES du vendeur par la clé publique de la CA en base64.
    aes_cipher = rsa_instance.crypter(sellerAesKey, caPubKey, True)
    if aes_cipher == None:
        return jsonify({'message': "ERROR SERVER: La clé AES du vendeur n'a pas pu être chiffré."}), 200
    
    print(f"SECRET EN BASE 64 :\n", aes_cipher)
    
    # Je construit le message à publié sur la file MQTT.
    message = {
        'code' : 2,
        'data' : aes_cipher
    }
        
    # Je publie le message.
    error = publish_message(os.getenv("TOPIC_PUBLISH_CA"), json.dumps(message))
    if error:
        return jsonify({'message': "ERROR SERVEUR: publication sur la file MQTT impossible."}), 200
     
    print(f"\n\n CLE AES CLIENT: ", sellerAesKey)
    return jsonify({'message': "Le secrêt vient d'être publié sur la file MQTT."}), 200
