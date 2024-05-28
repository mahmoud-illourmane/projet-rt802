from flask import jsonify, request
from flask import Blueprint

import sys, os, json
import asyncio

api_bp = Blueprint('api', __name__)

# Ajoute le chemin du dossier parent à sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import en relation avec la file MQTT
from .mqtt import publish_message

#
#   ROUTES
#

@api_bp.route('/client/api/hello', methods=['GET'])
def hello():
    if request.method == 'GET':
        available = {
            'bool': "True"
        }
        return jsonify(available), 200
    
    return jsonify({
        "error": "Method Not Allowed"
    }), 405

#
#   Opérations internes au client
#

#
#   CREATE
#

@api_bp.route('/client/api/generate-rsa-key', methods=['GET'])
def generateRSAKey():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    from app import rsa_instance
    
    check_rsa = rsa_instance.get_my_pub_key()
    if not check_rsa:
        rsa_instance.generate_keys()
        return jsonify({'message': "Clés générées avec succès."}), 200
    else:
        return jsonify({'message': "Des clés RSA sont déjà présentes sur le client."}), 200
    
@api_bp.route('/client/api/generate-aes-key', methods=['GET'])
def generateAESKey():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    from app import aes_instance
    
    check_aes = aes_instance.get_my_aes_key()
    if not check_aes:
        aes_instance.generate_key()
        return jsonify({'message': "Clé AES générée avec succès."}), 200
    else:
        return jsonify({'message': "Une clé AES existe déjà sur le client."}), 200
    
#
#   VERIFY
#

@api_bp.route('/client/api/check-rsa-key', methods=['GET'])
def checkRSAKey():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405    
    from app import rsa_instance
    
    check_rsa = rsa_instance.get_my_pub_key()
    
    if check_rsa:
        return jsonify({'message': "Les clés RSA sont présentes."}), 200
    else:
        return jsonify({'message': "Aucune paire de clés RSA trouvée."}), 200

@api_bp.route('/client/api/check-aes-key', methods=['GET'])
def checkAESKey():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import aes_instance
    
    check_aes = aes_instance.get_my_aes_key()
    if check_aes:
        return jsonify({'message': "Clé AES présente."}), 200
    else:
        return jsonify({'message': "Aucune clé AES trouvée."}), 200
    
#   END
#   Opérations internes au client
#   =============================

#   START
#   Opérations externes au client
#

#   == OPERATION WITH ==
#
#   ======== CA ========
#
#   ====================

#
#   GET PUB KET CA
#

@api_bp.route('/client/api/get-pub-key-ca', methods=['GET'])
async def getPubKeyCa():
    """
        Cette route permet de demander la clé publique de la CA.
        Le client publie sur la file MQTT la demande.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    message = {
        'code' : 1,
        'data' : None
    }
    
    print("CLIENT : Demande de la clé publique à la CA sur MQTT.")
    publish_message(os.getenv("TOPIC_PUBLISH_CA"), json.dumps(message))
    
    return jsonify({'message': "ok"}), 200

@api_bp.route('/client/api/print-pub-key-ca', methods=['GET'])
async def printPubKeyCa():
    """
        Cette route sert juste à afficher la clé publique de la CA
        sur la vue.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import rsa_instance

    await asyncio.sleep(1)  # Attend une seconde pour être sur que la clé est bien stocké dans la classe à cause du traitement MQTT.
    
    caPubKey = rsa_instance.get_pub_key("ca", True)
    if not caPubKey:
        return jsonify({'data': "CLIENT: Vous n'avez pas la clé publique de la CA."}), 200
    elif caPubKey == -1:
        return jsonify({'data': "CLIENT: Erreur lors de l'extraction de la clé publique de la CA."}), 200
    
    message = {
        'data' : caPubKey
    }
    return jsonify({'message': message}), 200

#
#   SECRET EXCHANGE CA
#

@api_bp.route('/client/api/secret-exchange-ca', methods=['GET'])
def secretExchangeCa():
    """
        Cette route, permet d'entamer le processus d'échange
        de secret entre le client et la CA. Il publie la 
        demande sur la file MQTT.
        
        Le client a besoin d'avoir :
            - De sa clé publique AES.
            - De la clé publique de la CA.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import rsa_instance, aes_instance

    # Je récupère la clé publique de la CA depuis l'instance RSA du client.
    caPubKey = rsa_instance.get_pub_key("ca")
    if caPubKey == None:
        return jsonify({'message': "ERROR SERVER: La clé publique de la CA est introuvable."}), 200
    
    # Je récupère la clé AES du client depuis l'instance AES du client.
    clientAesKey = aes_instance.get_my_aes_key()
    if clientAesKey == None:
        return jsonify({'message': "ERROR SERVER: La clé AES du client est introuvable."}), 200
    
    # Je crypte la clé AES du client par la clé publique de la CA en base64.
    aes_cipher = rsa_instance.crypter(clientAesKey, caPubKey, True)
    if aes_cipher == None:
        return jsonify({'message': "ERROR SERVER: La clé AES du client n'a pas pu être chiffrée."}), 200
     
    # Je construis le message à publier sur la file MQTT.
    message = {
        'code' : 2,
        'data' : aes_cipher
    }
        
    # Je publie le message.
    error = publish_message(os.getenv("TOPIC_PUBLISH_CA"), json.dumps(message))
    if error:
        return jsonify({'message': "ERROR SERVEUR: publication sur la file MQTT impossible."}), 200
    
    return jsonify({'message': "Le secret vient d'être publié sur la file MQTT."}), 200


#   ====================
#
#   ====== SELLER ======
#
#   ====================

#
#   GET PUB KET SELLER
#

@api_bp.route('/client/api/get-pub-key-seller', methods=['GET'])
def getPubKeySeller():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    message = {
        'code' : 1,
        'data' : None
    }
    
    error = publish_message(os.getenv("TOPIC_PUBLISH_SELLER"), json.dumps(message))
    if error == -1:
        print("Error publish to topic seller.")
        return jsonify({'message': "Error publish to topic seller."}), 200
    
    return jsonify({'message': "ok"}), 200

@api_bp.route('/client/api/print-pub-key-seller', methods=['GET'])
async def printPubKeySeller():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import rsa_instance
    
    await asyncio.sleep(1)
    
    caPubKey = rsa_instance.get_pub_key("seller", True)
    if caPubKey == -1:
        return jsonify({'message': "ERROR SERVER: CaPubKey not found."}), 200

    message = {
        'code' : 1,
        'data' : caPubKey
    }

    return jsonify({'message': message}), 200