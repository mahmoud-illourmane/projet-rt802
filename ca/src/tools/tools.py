import os, sys
from datetime import datetime, timedelta

# Ajoute le chemin du répertoire parent au chemin de recherche des modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def receive_exchange_secret_client(rsa_instance, aes_instance, dataBase64):
    """
        Cette fonction sert à récuperer le secrêt envoyer par 
        le client.
        Elle décrypte la clé AES, et l'ajoute au dictionnaire de la CA.
        
    Args:
        rsa_instance (ChiffrementRSA): L'instance de la CA.
        aes_instance (ChiffrementAES): L'instance de la CA.
        dataBase64 (Base64): La chaîne reçu encodée en base64 et crypté en RSA.
    """
    from app import rsa_instance, aes_instance
    
    # J'enlève le base64
    rsa_cipher = rsa_instance.decrypt_cipher_base64(dataBase64)
    if rsa_cipher == None:
        return None
    print("\n\nSECRET SANS BASE64 :\n", rsa_cipher)
    
    decrypted_aes_key = rsa_instance.decrypter(rsa_cipher)
    if decrypted_aes_key == None:
        return None
    
    print(f"CLE AES DECRYPTEE : ", decrypted_aes_key)
    aes_instance.insert_aes(decrypted_aes_key, "client")
    


def write_log(entry, filename="server_log.txt"):
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