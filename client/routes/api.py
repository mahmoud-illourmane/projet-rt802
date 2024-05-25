from app import app
from flask import jsonify, request

from src.classes.tools import write_log
from encryption.rsa import ChiffrementRSA
from encryption.aes import ChiffrementAES

@app.route('/client/api/hello', methods=['GET'])
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
#   Creations
#

@app.route('/client/api/generate-rsa-key', methods=['GET'])
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
    
@app.route('/client/api/generate-aes-key', methods=['GET'])
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
#   Checks
#

@app.route('/client/api/check-rsa-key', methods=['GET'])
def checkRSAKey():
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
        
    chiffrementRSA = ChiffrementRSA()
    check_rsa = chiffrementRSA.a_paire_de_cles_rsa()
    
    if check_rsa:
        return jsonify({'message': "Clés RSA présentes."}), 200
    else:
        return jsonify({'message': "Aucune paire de clés RSA trouvée."}), 200

@app.route('/client/api/check-aes-key', methods=['GET'])
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

