from app import app       
from flask import jsonify, request
import json, datetime

from src.classes.tools import write_log
from encryption.rsa import ChiffrementRSA

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

@app.route('/ca/api/hello', methods=['GET'])
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
#   RSA Toolstack
#

@app.route('/ca/get-public-key', methods=['GET'])
def get_public_key():
    if request.method == 'GET':
        chiffrement = ChiffrementRSA()
        public_key = chiffrement.charger_cle_publique()
        return public_key.export_key().decode('utf-8')+"\n", 200
    else:
        return "Method Not Allowed", 405

@app.route('/ca/create-certificat', methods=['POST'])
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
        return "Method Not Allowed", 405