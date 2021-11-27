from json_storage import JsonStore


class Account_Storage(JsonStore):
    _FILE_PATH = "D:/PyCharm/Proyectos/CryptoProject2/JsonFiles/Accounts.json"
    #_FILE_PATH = "C:/Users/madrid/PycharmProjects/CryptoProject/JsonFiles/Accounts.json"

    def __init__(self):
        super().__init__()
