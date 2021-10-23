from json_storage import JsonStore


class User_Storage(JsonStore):
    _FILE_PATH = "D:/PyCharm/Proyectos/CryptoProject/JsonFiles/Users.json"

    def __init__(self):
        super().__init__()

