from flask import jsonify, request
from flask import Blueprint

import sys, os

api_bp = Blueprint('api', __name__)

# Ajoute le chemin du dossier parent à sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# from tools.tools import write_log
from encryption.rsa import ChiffrementRSA
from encryption.aes import ChiffrementAES

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

@api_bp.route('/ca/get-public-key', methods=['GET'])
def get_public_key():
    if request.method == 'GET':
        chiffrement = ChiffrementRSA()
        public_key_pem = chiffrement.exporter_cle_publique_pem()
        return jsonify(public_key_pem + "\n"), 200
    else:
        return jsonify({"error": "Method Not Allowed"}), 405


@api_bp.route('/ca/create-certificat', methods=['POST'])
def create_csr():
    if request.method == 'POST':
        data = request.json
        
        if data:
            print("Données reçues :")
            print(f"nom : {data["common_name"]}")
            print(f"organization : {data["organization"]}")
            print(f"country : {data["country"]}")
            print(f"public_key : {data["public_key"]}")
            
            # for key, value in data.items():
            #     print(f"{key}: {value}")
            return "Données reçues avec succès", 200
        else:
            return "Aucune donnée reçue", 400
    else:
        return jsonify({"error": "Method Not Allowed"}), 405