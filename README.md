# projet-rt802
Projet universitaire RT0802 échanges sécurisés et PKI

# Prérequis

## Installer les dépendances nécessaires
```bash
pip install -r requirements.txt
```
ou 
```bash
pip3 install -r requirements.txt
```

# Structure du projet
Vous trouverez le fichier "schema.drawio" où la majorité des composantes du projet sont décrites. N'hésitez pas à le consulter.

# Configurer les .env
Vous devez configurer les fichiers ".env" de chaque serveur. Le port MQTT est indiqué en dur dans les fichiers app.py de chaque serveur.

# Choix du lancement

## Lancer chaque serveur manuellement
Vous pouvez lancer chaque serveur de manière individuelle en vous positionnant au niveau du script "app.py" de chaque serveur avec la commande :

/ca/ :
```bash
python3 app.py
```

/client/ :
```bash
python3 app.py
```

/vendeur/ :
```bash
python3 app.py
```

## launcher.py
Un script nommé launcher.py se trouve à la racine du projet. Il utilise des threads pour lancer le projet dans un seul terminal. Un affichage des logs est mis en place de manière dynamique. Attention, pour arrêter les threads, il faudra fermer le terminal.
```bash
python3 launcher.py
```

## Lancement de l'interface web Vue.js
Une fois les dépendances installées et les serveurs démarrés, ouvrez le fichier "projet.html" dans un navigateur compatible JavaScript. Les liens CDN sont utilisés dans ce fichier html, donc aucune installation de Vue.js n'est nécessaire.
```bash
projet.html
```