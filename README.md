# projet-rt802
Projet universitaire RT0802 échanges sécurisés et PKI

# Prérequis

## Installer les dépendances nécessaires
```bash
pip install -r requirements.txt
```

# Choix du lancement

## launcher.py
Un script nommé launcher.py se trouve à la racine du projet. Il utilise des threads pour lancer le projet dans un seul terminal. Un affichage des logs est mis en place de manière dynamique. Attention, pour arrêter les threads, il faudra fermer le terminal.
```bash
launcher.py
```

## Lancer chaque serveur manuellement
Vous pouvez également lancer chaque serveur de manière individuelle en vous positionnant au niveau du script "app.py" de chaque serveur avec la commande :
```bash
python app.py
```

## Lancement de l'interface web Vue.js
Une fois les dépendances installées et les serveurs démarrés, ouvrez le fichier "projet.html" dans un navigateur compatible JavaScript. Les liens CDN sont utilisés dans ce fichier html, donc aucune installation de Vue.js n'est nécessaire.
```bash
projet.html
```