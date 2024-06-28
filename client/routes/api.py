from flask import jsonify, request
from flask import Blueprint

import sys, os, json
import asyncio

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

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
    """
        Cette route sert à créer des clés AES pour les utiliser
        soit avec le CA soit pour le Vendeur.
        
        Args:
            name (str): Un identifiant pour catégoriser la clé AES ['ca', 'seller']
        Returns:
            json: response
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import aes_instance
    
    # Le nom de l'identifiant pour qui générer une clé AES.
    name = request.args.get('name')
    if name not in ['ca', 'seller']:
        return jsonify({'message': "ERROR: Unknown name identifier."}), 200
    
    # Je vérifie que la clé n'existe pas déjà.
    check_aes = aes_instance.aes_key_exist(name)
    if check_aes:
        return jsonify({'message': f"La Clé AES à utiliser avec '{name}' est déjà présente."}), 200
    else:
        new_key = aes_instance.generate_key()
        aes_instance.insert_aes_key(new_key, name)
        return jsonify({'message': f"La clé AES à utiliser avec '{name}' a été générée."}), 200
    
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
    """
        Cette route permet de vérifier la présence des clés AES à utiliser
        avec les différentes entités [ca, vendeur].
        
        Returns:
            json: response Bool
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import aes_instance
    
    name = request.args.get('name')
    if name not in ['ca', 'seller']:
        return jsonify({'message': "ERROR: Unknown name identifier."}), 200
    
    check_aes = aes_instance.aes_key_exist(name)
    if check_aes:
        return jsonify({'message': f"La Clé AES à utiliser avec '{name}' est présente."}), 200
    else:
        return jsonify({'message': f"Aucune clé AES n'a été trouvée pour le domaine '{name}'."}), 200
    
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

@api_bp.route('/client/api/get-all-aes-key', methods=['GET'])
def getAllAesKeys():
    """
        Cette route permet de retourner toutes les clé
        AES que le vendeur dispose.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import aes_instance
    
    aes_keys_dic = aes_instance.get_all_aes_keys()
    print("TOUTES LES CLE AES:\n",aes_keys_dic)
    response = {'aes_keys_dic': aes_keys_dic}
    
    return jsonify(response), 200


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
            - La clé AES utilisé pour les échanges avec la CA.
            - La clé publique de la CA.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import rsa_instance, aes_instance

    # Je récupère la clé publique de la CA depuis l'instance RSA du client.
    caPubKey = rsa_instance.get_pub_key("ca")
    if caPubKey == None:
        return jsonify({'message': "ERROR SERVER: La clé publique de la CA est introuvable."}), 200
    
    # Je récupère la clé AES a utiliser pour la communication avec la CA depuis l'instance AES du client.
    aesKey = aes_instance.get_aes_key("ca")
    if aesKey == None:
        return jsonify({'message': "ERROR SERVER: La clé AES utilise pour les échanges avec la CA est introuvable."}), 200
    
    # Je crypte la clé AES par la clé publique de la CA en base64.
    aes_cipher_base64 = rsa_instance.crypter(aesKey, caPubKey, True)
    if aes_cipher_base64 == None:
        return jsonify({'message': "ERROR SERVER: La clé AES du client n'a pas pu être chiffrée."}), 200
     
    # Je construis le message à publier sur la file MQTT.
    message = {
        'code' : 2,
        'data' : aes_cipher_base64
    }
    
    print("\n\nAES SENDED: ", aesKey)
    
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

@api_bp.route('/client/api/get-seller-certificate', methods=['GET'])
def getSellerCertificate():
    """
        Cette route permet de demander le certificat d'un vendeur.
        
        Elle publie un message sur la file MQTT en utilisant le code 4.
        Lorsque le vendeur aura publié son certificat sur le topic du client,
        le client le récupère.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import aes_instance, rsa_instance
    
    # Vérifications des clés
    
    # Disponibilité de la clé publique de la CA pour pouvoir demander la vérification du certificat du vendeur si besoin.
    caPubKey = rsa_instance.get_pub_key("ca", True) 
    if caPubKey is None:
        return jsonify({'message': 'ERREUR : La clé publique de la CA est introuvable.'}), 200
    
    # Disponibilité de la clé AES de communication avec le vendeur.
    sellerAesKey = aes_instance.get_aes_key("seller")
    if sellerAesKey is None:
        return jsonify({'message': 'ERREUR : La clé AES utilisé avec le vendeur est introuvable.'}), 200
    
    # Donnée à envoyer
    message = {
        'code' : 4,
        'data' : None
    }
    
    # Publication du message sur la file MQTT
    error = publish_message(os.getenv("TOPIC_PUBLISH_SELLER"), json.dumps(message))
    if error == -1:
        print("ERREUR : Impossible de publier sur la file MQTT (getSellerCertificate).")
        return jsonify({'message': "ERREUR : Impossible de publier sur la file MQTT."}), 200
    
    return jsonify({'message': 'ok.'}), 200

@api_bp.route('/client/api/verify-seller-certificate', methods=['GET'])
async def verifySellerCertificate():
    """
        Cette route permet de vérifier la validité d'un certificat en local.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    
    from app import rsa_instance, certificat_instance   # Importation de l'instance qui détient le certificat du vendeur côté client
    
    await asyncio.sleep(1)  # J'attends une seconde pour laisser du temps à la sauvegarde du certificat reçu éventuellement par l'appel précédent
    
    # Je récupère le certificat du vendeur sauvegarder en local sur le client
    cert = certificat_instance.get_certificate()
    if cert is None:
        return jsonify({'message': "Aucun certificat n'est disponible pour la vérification."}), 200
    print("LE CERTIFICAT:\n", cert)
    
    # Le client stocke la clé publique de la CA. Elle est retournée pour être utilisée
    pubKey = rsa_instance.get_pub_key("ca")
    if not isinstance(pubKey, RSAPublicKey):
        return jsonify({'message': 'Erreur La clé de la CA est introuvable.'}), 200
    print("PUBKEY\n", pubKey)
    
    try:
        verification = certificat_instance.verify_certificat(cert, pubKey)
    except Exception as e:
        print(f"Erreur lors de la vérification du certificat : {e}")
        return jsonify({'message': f'Erreur lors de la vérification du certificat : {e}'}), 200
    
    if verification == True:
        result = "valide"
    else:
        result = "invalide"
        
    return jsonify({'message': f"Le certificat est {result}"}), 200

@api_bp.route('/client/api/verify-seller-certificate/with-ca', methods=['GET'])
def verifySellerCertificateWithCaSend():
    """
        Cette route demande la vérification d'un certificat en demandant à la CA 
        s'il est révoqué.
        On chiffre le certificat en AES, puis le message est publié sur la file MQTT sur le
        topic où la CA est abonnée.
        Code de la requête 3.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import aes_instance, certificat_instance
    
    # Récuperation le certificat du vendeur stocker sur le client
    cert = certificat_instance.get_certificate()
    if cert is None:
        return jsonify({'message': "Aucun certificat n'est disponible pour la vérification."}), 200
    
    # Récupération de la clé AES de communication avec la CA
    aesKey = aes_instance.get_aes_key("ca")
    if aesKey is None:
        return jsonify({'message': "Il manque la clé AES de communication avec la CA."}), 200
    
    # Chiffrement du certificat
    cert_encrypted = aes_instance.encrypt(cert, aesKey, True)
    if cert_encrypted is None:
        return jsonify({'message': "Erreur lors de la tentative de cryptage du certificat du vendeur."}), 200
    
    # Données à envoyer
    message = {
        'code' : 3,
        'data' : cert_encrypted
    }
    
    # Publication du message
    error = publish_message(os.getenv("TOPIC_PUBLISH_CA"), json.dumps(message))
    if error == -1:
        print("Error publish to topic ca.")
        return jsonify({'message': "Error publish to topic ca."}), 200
    print("TOPIC CA : Le certificat du vendeur a été publié sur la file MQTT.")
    
    return jsonify({'message': "ok"}), 200

@api_bp.route('/client/api/print-response-ca', methods=['GET'])
async def printResponseCa():
    """
        Cette route sert à afficher le résultat de la demande
        de vérification de révocation demandé à la CA.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import certificat_instance
    
    # J'attend une seconde entre l'appel de la route verifySellerCertificateWithCaSend et printResponseCa
    await asyncio.sleep(1)
    
    result = certificat_instance.getResponseCa()
    if result:
        res = "Certificat Révoqué"
    else:
        res = "Certificat non révoqué"
    return jsonify({'message': f"{res}"}), 200


@api_bp.route('/client/api/secret-exchange-seller', methods=['GET'])
def secretExchangeSeller():
    """
        Cette route, permet d'entamer le processus d'échange
        de secret entre le client et le vendeur. Il publie la 
        demande sur la file MQTT.
        
        Le client a besoin d'avoir :
            - La clé AES utilisé pour les échanges avec la CA.
            - La clé publique de la CA.
    """
    if request.method != 'GET':
        return jsonify({"error": "Method Not Allowed"}), 405
    from app import rsa_instance, aes_instance

    # Je récupère la clé publique de la CA depuis l'instance RSA du client.
    caPubKey = rsa_instance.get_pub_key("seller")
    if caPubKey == None:
        return jsonify({'message': "ERROR SERVER: La clé publique du vendeur est introuvable."}), 200
    
    # Je récupère la clé AES a utiliser pour la communication avec la CA depuis l'instance AES du client.
    aesKey = aes_instance.get_aes_key("seller")
    if aesKey == None:
        return jsonify({'message': "ERROR SERVER: La clé AES utilisé pour les échanges avec le vendeur est introuvable."}), 200
    
    # Je crypte la clé AES par la clé publique de la CA en base64.
    aes_cipher_base64 = rsa_instance.crypter(aesKey, caPubKey, True)
    if aes_cipher_base64 == None:
        return jsonify({'message': "ERROR SERVER: La clé AES du client n'a pas pu être chiffrée."}), 200
     
    # Je construis le message à publier sur la file MQTT.
    message = {
        'code' : 3,
        'data' : aes_cipher_base64
    }
    
    print("\n\nAES SENDED: ", aesKey)
    
    # Je publie le message.
    error = publish_message(os.getenv("TOPIC_PUBLISH_SELLER"), json.dumps(message))
    if error:
        return jsonify({'message': "ERROR SERVEUR: publication sur la file MQTT impossible."}), 200
    
    return jsonify({'message': "Le secret entre client/vendeur vient d'être publié sur la file MQTT."}), 200

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