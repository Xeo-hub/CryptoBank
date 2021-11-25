from json_storage import JsonStore
from pathlib import Path

class User_Salt_Storage(JsonStore):
    _FILE_PATH = "C:/Users/madrid/PycharmProjects/CryptoProject/JsonFiles/User_salt.json"

    def __init__(self):
        super().__init__()