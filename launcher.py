import subprocess
import threading
import os
import sys

# Drapeau pour indiquer aux threads de s'arrêter
exit_flag = threading.Event()

# Chemin absolu du répertoire de travail du script
project_dir = os.path.abspath(os.path.dirname(__file__))

# Fonction pour lancer un serveur Flask
def launch_server(command, working_directory, log_file):
    process = subprocess.Popen(command, shell=True, cwd=working_directory, stdout=open(log_file, 'w'), stderr=subprocess.STDOUT)
    while not exit_flag.is_set():
        if process.poll() is not None:  # Vérifie si le processus est terminé
            break
        else:
            exit_flag.wait(timeout=1)  # Attendez 1 seconde avant de vérifier à nouveau

    # Arrêtez le processus si ce n'est pas déjà fait
    if process.poll() is None:
        process.terminate()


# Commandes pour lancer les serveurs avec les chemins corrects
commands = [
    ("python app.py", "ca", "ca.log"),        
    ("python app.py", "vendeur", "vendeur.log"),   
    ("python app.py", "client", "client.log")     
]

# Lancement des serveurs dans des threads différents
threads = []
for command, folder, log_file in commands:
    thread = threading.Thread(target=launch_server, args=(command, os.path.join(project_dir, folder), os.path.join(project_dir, folder, log_file)))
    thread.daemon = True
    threads.append(thread)
    thread.start()

# Fonction pour afficher les logs d'un serveur
def display_logs(log_file):
    os.system('cls' if os.name == 'nt' else 'clear')
    with open(log_file, 'r') as file:
        print(file.read())

# Fonction pour nettoyer les logs d'un serveur
def clean_logs(log_file):
    if os.path.exists(log_file):
        os.remove(log_file)

# Boucle du menu
while True:
    print("Sélectionnez une option:")
    print("1 : Afficher les logs du serveur CA")
    print("2 : Afficher les logs du serveur Vendeur")
    print("3 : Afficher les logs du serveur Client")
    print("4 : Quitter")

    choice = input("Entrez votre choix: ")

    if choice == '1':
        display_logs(os.path.join(project_dir, 'ca', 'ca.log'))
    elif choice == '2':
        display_logs(os.path.join(project_dir, 'vendeur', 'vendeur.log'))
    elif choice == '3':
        display_logs(os.path.join(project_dir, 'client', 'client.log'))
    elif choice == '4':
        print("Arrêt du programme.")
        # Indiquer aux threads de s'arrêter
        exit_flag.set()
        # Attendre que tous les threads se terminent
        for thread in threads:
            thread.join()
        sys.exit()

    else:
        print("Choix invalide. Veuillez réessayer.")
