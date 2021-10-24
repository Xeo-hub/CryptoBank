from json_storage import JsonStore


class Key_Storage(JsonStore):
    _FILE_PATH = "D:/PyCharm/Proyectos/CryptoProject/JsonFiles/Money_Keys.json"

    def __init__(self):
        super().__init__()

