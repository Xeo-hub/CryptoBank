from json_storage import JsonStore


class Hmac_Storage(JsonStore):
    _FILE_PATH = "C:/Users/Pablo/PycharmProjects/CryptoProject/JsonFiles/Hmac_data.json"

    def __init__(self):
        super().__init__()

