from json_storage import JsonStore


class Account_Storage(JsonStore):
    _FILE_PATH = "D:/PyCharm/Proyectos/CryptoProject/JsonFiles/Accounts.json"

    def __init__(self):
        super().__init__()
