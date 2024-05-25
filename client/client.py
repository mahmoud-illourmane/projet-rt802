from src.classes.tools import *
from encryption.rsa import ChiffrementRSA
from encryption.aes import ChiffrementAES
from src.classes.certificat import Certificat

def main():
    """
        Fonction principale du programme.
    """
    chiffrementRSA = ChiffrementRSA()
    chiffrementAES = ChiffrementAES()
    quit = False

    while not quit:
        try:
            choice = display_menu()
            
            if choice == "1": # Vérifier les clés à disposition
                check_rsa = chiffrementRSA.a_paire_de_cles_rsa()
                check_aes = chiffrementAES.a_paire_de_cles_aes()
                print(f"CLES A DISPOSITONS:\nCLES RSA : {check_rsa}\nCLE AES : {check_aes}")
                
            elif choice == "2": # Générer une paire de clés RSA
                chiffrementRSA.generer_cles()
                
            elif choice == "3": # Générer une clé AES de 32 bites
                chiffrementAES.generate_key()
                
            elif choice == "4": # Récupérer la clé publique de CA
                pub_key_ca = chiffrementRSA.recuperer_pub_ca()
                print(pub_key_ca)
                
            elif choice == "5": # Demander un certificat à CA
                certificat = Certificat()
                certificat.send_certificat_data()
             
            elif choice == "6": # Vérifier un certificat
                print("TODO")
                #TODO
                
            elif choice.lower() == "quit":
                quit = True
                
            else:
                print(f"Choix invalide : {choice}")
        except ValueError as e:
            print(f"Erreur : {e}")

def display_menu():
    """
        Affiche le menu et retourne le choix de l'utilisateur.
    """
    print(f"\n{COLOR_RED}====================")
    print(f"========MENU========")
    print(f"===================={COLOR_END}\n")
    
    print(f"1- Vérifier les clés à disposition")
    print(f"2- Générer une paire de clés RSA")
    print(f"3- Générer une clé AES de 32 bites")
    print(f"4- Récupérer la clé publique de CA")
    print(f"5- Demander un certificat à CA")
    print(f"6- Vérifier un certificat\n")
    
    print(f"{COLOR_YELLOW}QUIT pour quitter.{COLOR_END}")
    
    return input(f"\nEntrez votre choix : ")

# Implémentation des autres fonctions du menu

if __name__ == "__main__":
    main()
