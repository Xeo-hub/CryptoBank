from json_storage import JsonStore
from pathlib import Path

class Account_Salt_Storage(JsonStore):
    _FILE_PATH = "C:/Users/madrid/PycharmProjects/CryptoProject/JsonFiles/Account_salt.json"

    def __init__(self):
        super().__init__()