from json_storage import JsonStore
from pathlib import Path

class Scrypt_Storage(JsonStore):
    # _FILE_PATH = str(Path.home()) + "/PyCharm/Proyectos/CryptoProject/JsonFiles/Scrypt_storage.json"
    _FILE_PATH = "D:/PyCharm/Proyectos/CryptoProject/JsonFiles/Scrypt_storage.json"

    def __init__(self):
        super().__init__()