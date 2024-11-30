import subprocess
import threading
import os
import sys
import signal

# Drapeau pour indiquer aux threads de s'arrêter
exit_flag = threading.Event()

# Chemin absolu du répertoire de travail
project_dir = os.path.abspath(os.path.dirname(__file__))

def launch_server(command, working_directory, log_file):
    with open(log_file, 'w') as log:
        # Configurer le processus en fonction de l'OS
        if os.name == 'nt':  # Windows
            process = subprocess.Popen(
                command,
                cwd=working_directory,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
        else:  # Unix/Linux
            process = subprocess.Popen(
                command,
                cwd=working_directory,
                stdout=log,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid
            )
        
        try:
            while not exit_flag.is_set():
                if process.poll() is not None:
                    break
                exit_flag.wait(timeout=1)
        finally:
            if process.poll() is None:
                if os.name == 'nt':  # Windows
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                else:  # Unix/Linux
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)

# Détection automatique du bon exécutable Python
python_executable = "python3" if sys.platform != "win32" else "python"

# Commandes à exécuter
commands = [
    ([python_executable, "app.py"], "ca", "ca.log"),
    ([python_executable, "app.py"], "vendeur", "vendeur.log"),
    ([python_executable, "app.py"], "client", "client.log")
]

# Lancement des serveurs dans des threads
threads = []
for command, folder, log_file in commands:
    thread = threading.Thread(
        target=launch_server,
        args=(command, os.path.join(project_dir, folder), os.path.join(project_dir, folder, log_file))
    )
    thread.start()
    threads.append(thread)

# Menu principal
while True:
    print("Sélectionnez une option:")
    print("1 : Afficher les logs du serveur CA")
    print("2 : Afficher les logs du serveur Vendeur")
    print("3 : Afficher les logs du serveur Client")
    print("4 : Quitter")

    choice = input("Entrez votre choix: ")

    if choice == '1':
        print(open(os.path.join(project_dir, 'ca', 'ca.log')).read())
    elif choice == '2':
        print(open(os.path.join(project_dir, 'vendeur', 'vendeur.log')).read())
    elif choice == '3':
        print(open(os.path.join(project_dir, 'client', 'client.log')).read())
    elif choice == '4':
        print("Arrêt des serveurs en cours...")
        exit_flag.set()
        for thread in threads:
            thread.join()
        sys.exit()
    else:
        print("Choix invalide. Veuillez réessayer.")
