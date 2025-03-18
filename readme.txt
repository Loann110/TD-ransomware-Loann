1. Rôle des fichiers python

ransomware.py : Programme principal qui chiffre des fichiers et envoie la clé au serveur.

xorcrypt.py : Gère le chiffrement et le déchiffrement avec XOR.

secret_manager.py : Stocke et gère la clé de chiffrement côté serveur.

cncbase.py : Contient les fonctions pour faire tourner le serveur de commande.

cnc.py : Démarre le serveur et reçoit la clé envoyée par le ransomware.


2. Algorithme de chiffrement utilisé

Le ransomware utilise XOR.

XOR est une opération simple et réversible :

Chiffrer : donnée XOR clé

Déchiffrer : donnée_chiffrée XOR clé (on retrouve la donnée originale).

Si la clé est connue, le chiffrement peut être annulé.


3. Génération et stockage de la clé

Une clé aléatoire est générée quand le ransomware s'exécute.

La clé est envoyée au serveur C&C via une requête HTTP.

Le serveur la stocke pour que l'attaquant puisse la récupérer.

Sans cette clé, les fichiers restent chiffrés


4. Communication entre ransomware et serveur

Le ransomware chiffre les fichiers et envoie la clé au serveur C&C.

Le serveur C&C reçoit la clé et la stocke.

Tout se fait en réseau via HTTP (pas sécurisé).


5. Déchiffrement des fichiers

Si la clé est récupérée depuis le serveur C&C :

On applique XOR à nouveau avec la même clé sur les fichiers chiffrés.

Cela restaure les fichiers d'origine.

Sans la clé : les fichiers sont perdus.


6. Commandes utiles

Démarrer le serveur C&C : python3 cnc.py

Exécuter le ransomware : python3 ransomware.py

Ajouter tous les fichiers à Git : git add .

Valider les changements : git commit -m "Mise à jour"

Envoyer sur GitHub : git push