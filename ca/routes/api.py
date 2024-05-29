from flask import jsonify, request
from flask import Blueprint

import sys, os

api_bp = Blueprint('api', __name__)

# Ajoute le chemin du dossier parent à sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import en relation avec la file MQTT
from .mqtt import publish_message

"""
|
|   This file contains the REST API routes for the project.
|
|   Author: Mahmoud ILLOURMANE
|   Date: 27 Mars 2024
|
"""

"""
|   ===============
|   API REST ROUTES
|   ===============
"""

@api_bp.route('/ca/api/hello', methods=['GET'])
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
#   GET
#

@api_bp.route('/ca/api/get-all-aes-key', methods=['GET'])
def getAllAesKeys():
    """
        Cette route permet de retourner toutes les clé
        AES que la CA dispose.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import aes_instance
    
    aes_keys_dic = aes_instance.get_all_aes_keys()
    print("TOUTES LES CLE AES:\n",aes_keys_dic)
    response = {'aes_keys_dic': aes_keys_dic}
    return jsonify(response), 200

@api_bp.route('/ca/get-public-key', methods=['GET'])
def get_public_key():
    """
        Retourne la clé publique de la CA.

    Returns:
        public_key_str (PEM): La clé publique au format PEM.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    from app import rsa_instance
    
    public_key_str = rsa_instance.get_my_pub_key_pem()
    return jsonify({"data": public_key_str}), 200
    
#
#   VERIFY
#

@api_bp.route('/ca/check-ca-crl', methods=['GET'])
def check_ca_crl():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    from app import crl_instance
    if crl_instance.my_certificat == None:
        return jsonify({"data": "No certificat FOUND"}), 200
    
    my_str_certificat = crl_instance.my_certificat.decode('utf-8')
    return jsonify({"data": "Certificat trouvé : " + my_str_certificat}), 200
   
#   END
#   VERIFY
#

@api_bp.route('/ca/create-self-certificat', methods=['GET'])
def create_self_csr():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import crl_instance
    
    my_crl = crl_instance.generer_certificat_autosigne()
    my_str_crl = my_crl.decode('utf-8')

    return jsonify({"data": my_str_crl}), 200