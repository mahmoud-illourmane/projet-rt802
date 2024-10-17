import os
from datetime import datetime, timedelta

COLOR_RED = "\033[31m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_END = "\033[00m"

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