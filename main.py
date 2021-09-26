JSON_FILES_PATH = "D:/PyCharm/Proyectos/CryptoProject/JsonFiles/"
print(JSON_FILES_PATH)

from users import User

class CryptoBank:
    def create_account(self, id, password, acc_name, key):

        josete = User(id, password)
        # Descargar la base de datos de las cuentas

        # Comprobar si existe id/password
        # Si existe se le añade la cuenta
        # Si no, se crea de 0
        del josete
