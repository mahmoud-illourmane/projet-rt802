from flask import jsonify, request
from flask import Blueprint

import sys, os

api_bp = Blueprint('api', __name__)

# Ajoute le chemin du dossier parent à sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# from tools.tools import write_log
from encryption.rsa import ChiffrementRSA
from encryption.aes import ChiffrementAES

@api_bp.route('/vendeur/api/hello', methods=['GET'])
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
#   
#

@api_bp.route('/seller/get-public-key', methods=['GET'])
def get_public_key():
    if request.method == 'GET':
        chiffrement = ChiffrementRSA()
        public_key_pem = chiffrement.exporter_cle_publique_pem()
        return jsonify(public_key_pem + "\n"), 200
    else:
        return jsonify({"error": "Method Not Allowed"}), 405