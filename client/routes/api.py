from flask import jsonify, request
from flask import Blueprint

import sys, os, json
import asyncio

api_bp = Blueprint('api', __name__)

# Ajoute le chemin du dossier parent à sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# from tools.tools import write_log
from encryption.rsa import ChiffrementRSA
from encryption.aes import ChiffrementAES

# Import en relation avec la file MQTT
from .mqtt import mqtt, publish_message

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
        
    chiffrementRSA = ChiffrementRSA()
    check_rsa = chiffrementRSA.a_paire_de_cles_rsa()
    
    if not check_rsa:
        if chiffrementRSA.generer_cles() == -1:
            return jsonify({'error': "Erreur serveur."}), 500
        else:
            return jsonify({'message': "Clés générés avec succès."}), 200
    else:
        return jsonify({'message': "Des clés RSA existent déjà sur le client."}), 200
    
@api_bp.route('/client/api/generate-aes-key', methods=['GET'])
def generateAESKey():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
        
    chiffrementAES = ChiffrementAES()
    check_aes = chiffrementAES.a_cle_aes()
    
    if not check_aes:
        if chiffrementAES.generate_key() == -1:
            return jsonify({'error': "Erreur serveur."}), 500
        else:
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
        
    chiffrementRSA = ChiffrementRSA()
    check_rsa = chiffrementRSA.a_paire_de_cles_rsa()
    
    if check_rsa:
        return jsonify({'message': "Clés RSA présentes."}), 200
    else:
        return jsonify({'message': "Aucune paire de clés RSA trouvée."}), 200

@api_bp.route('/client/api/check-aes-key', methods=['GET'])
def checkAESKey():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
        
    chiffrementAES = ChiffrementAES()
    check_aes = chiffrementAES.a_cle_aes()
    
    if check_aes:
        return jsonify({'message': "Clé AES présente."}), 200
    else:
        return jsonify({'message': "Aucune clé AES trouvée."}), 200
    
#   END
#   Opérations internes au client
#


#   START
#   Opérations externes au client
#

#
#   GET PUB KET CA
#

@api_bp.route('/client/api/get-pub-key-ca', methods=['GET'])
async def getPubKeyCa():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    message = {
        'code' : 1,
        'data' : None
    }
    
    print("MQTT : Demande clé publique à la CA.")
    publish_message(os.getenv("TOPIC_PUBLISH_CA"), json.dumps(message))
    
    return jsonify({'message': "ok"}), 200

@api_bp.route('/client/api/print-pub-key-ca', methods=['GET'])
async def printPubKeyCa():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    rsaInstance = ChiffrementRSA()
    caPubKey = rsaInstance.charger_str_cle_publique_ca()
    if caPubKey == -1:
        return jsonify({'message': "CLIENT: ERROR SERVER."}), 500
    
    message = {
        'code' : 1,
        'data' : caPubKey
    }

    return jsonify({'message': message}), 200

#
#   GET PUB KET SELLER
#

@api_bp.route('/client/api/get-pub-key-seller', methods=['GET'])
def getPubKeySeller():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    print("MQTT : Demande clé publique au vendeur.")
    message = {
        'code' : 1,
        'data' : None
    }
    
    publish_message(os.getenv("TOPIC_PUBLISH_SELLER"), json.dumps(message))
    
    return jsonify({'message': "ok"}), 200

@api_bp.route('/client/api/print-pub-key-seller', methods=['GET'])
def printPubKeySeller():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    rsaInstance = ChiffrementRSA()
    caPubKey = rsaInstance.charger_str_cle_publique_seller()
    if caPubKey == -1:
        return jsonify({'message': "CLIENT: ERROR SERVER."}), 500
    
    message = {
        'code' : 1,
        'data' : caPubKey
    }

    return jsonify({'message': message}), 200