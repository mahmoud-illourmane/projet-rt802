import os, sys
from datetime import datetime, timedelta
from typing import Union, Tuple  # Retour de fonction [str|int]

# Ajoute le chemin du répertoire parent au chemin de recherche des modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def receive_exchange_secret(rsa_instance, aes_instance, dataBase64, sender):
    """
        Cette fonction sert à récuperer le secrêt envoyer par 
        le client ou le vendeur.
        Elle décrypte la clé AES, et l'ajoute au dictionnaire de la CA.
        
        Args:
            rsa_instance (ChiffrementRSA): L'instance RSA de la CA.
            aes_instance (ChiffrementAES): L'instance AES de la CA.
            dataBase64 (Base64): La chaîne reçu encodée en base64 et crypté en RSA.
            sender (str): De qui la CA reçoit le secret.
        
        Returns:

    """
    from app import rsa_instance, aes_instance

    # J'enlève l'encodage base64.
    rsa_cipher = rsa_instance.decode_base64_encoded_rsa_cipher(dataBase64)
    if rsa_cipher == None:
        print("Error rsa_instance.decrypt_cipher_base64(dataBase64)")
        return None
    
    # Je décrypte la clé AES.
    decrypted_aes_key = rsa_instance.decrypter(rsa_cipher)
    if decrypted_aes_key == None:
        print("Error rsa_instance.decrypter(rsa_cipher)")
        return None
    
    print("\n\nAFFICHAGE DE LA CLE DECRYPTE:\n", decrypted_aes_key, "\n\n")
    
    # J'ajoute la clé aes dans le dictionnaire des clés avec l'identifiant reçu dans "sender".
    aes_instance.insert_aes_key(decrypted_aes_key, sender)
    print("\n\nCLE AES AJOUTEE:\n", aes_instance.get_aes_key(sender))

def decrypt_data_request_certificat(aes_instance, aesKey, dataUserEncrypted, pubKeyEncrypted, used_base64=True) -> Union[Tuple[bytes, bytes], None]:
    """
        Cette fonction sert à décrypter les données cryptées en AES lors d'une demande de certificat de la part du vendeur.

        Args:
            aes_instance (ChiffrementAES): L'instance AES de la CA.
            aesKey (bytes): La clé AES du vendeur.
            dataUserEncrypted (Any): Les données cryptées.
            pubKeyEncrypted (Any): Les données cryptées.
            used_base64 (bool, optionnel): Indique si les données ont été encodées en base64. Par défaut, True.

        Returns:
            Tuple[bytes, bytes]: Les données décryptées.
            ou
            None: En cas d'erreur.

    """
    from app import aes_instance
    
    # Décryptage des données du vendeur
    dataUserDecrypted = aes_instance.decrypt(dataUserEncrypted, aesKey, used_base64)
    if dataUserDecrypted is None:
        print("Erreur lors du decryptage des données du vendeur pour le certificat.")
        return None
    
    # Décryptage de la clé publique du vendeur du vendeur
    pubKeyDecrypted = aes_instance.decrypt(pubKeyEncrypted, aesKey, used_base64)
    if pubKeyDecrypted is None:
        print("Erreur lors du decryptage des données du vendeur pour le certificat.")
        return None
    
    return dataUserDecrypted, pubKeyDecrypted

def write_log(entry, filename="ca_log.txt"):
    """
        Écrit une entrée dans un fichier log avec la date et l'heure actuelles.
        
        Args:
        - entry (str): L'entrée à écrire dans le fichier log.
        - filename (str): Le nom du fichier log. Par défaut, "server_log.txt".
    """
    
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    log_dir = os.path.join(base_dir, "logs")
    log_file_path = os.path.join(log_dir, filename)

    # Création du dossier logs si nécessaire
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Obtention de la date et de l'heure actuelles
    now = datetime.now() + timedelta(hours=1)
    date_time = now.strftime("%Y-%m-%d %H:%M:%S")

    # Écriture de l'entrée dans le fichier log
    with open(log_file_path, "a") as file:
        file.write(f"{date_time} - {entry}\n")

    # Donne des autorisations pour supprimer le fichier
    os.chmod(log_file_path, 0o666) 