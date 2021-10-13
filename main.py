JSON_FILES_PATH = "D:/PyCharm/Proyectos/CryptoProject/JsonFiles/"
print(JSON_FILES_PATH)

from users import User
from json_storage import JsonStore

class CryptoBank:
    def create_account(self, id, password, acc_name, key):

        user = User(id, password)
        accounts_storage = JsonStore()
        accounts=accounts_storage.load_store()
        account=accounts.find_item(user)
        # Descargar la base de datos de las cuentas

        # Comprobar si existe id/password
        # Si existe se le añade la cuenta
        # Si no, se crea de 0
        del user

    def login(self, id, password):
       self.verify (id, password)

    def verify (self,id, password:None):
        accounts_storage = JsonStore()
        accounts = accounts_storage.load_store()
        if password == None:
            for item in accounts:
                for element in item.keys():
                    if id in element:
                        print("Busca otro nombre crack")
            return

        user = User(id, password)
        for item in accounts:
            if user in item.keys():
                print("Sesión iniciada")
                user.accounts=[]######
        print("Error")


    def delete_account(self, id, password, acc_name, key):
        # Descargar la base de datos de las cuentas
        # Comprobar si existe id/password
        # Si existe buscamos la cuenta
        # La borramos
        # Si no, mandamos un warning
        pass

    def modify_account(self, id, password, acc_name, key):
        # Descargar la base de datos de las cuentas
        # Comprobar si existe id/password
        # Si existe buscamos la cuenta
        # La modificamos
        # Si no, mandamos un warning
        pass

    def deposit(self, id, password, acc_name, key):
        # Descargar la base de datos de las cuentas
        # Comprobar si existe id/password
        # Si existe buscamos la cuenta
        # Sumamos el dinero
        # Si no, mandamos un warning
        pass

    def withdraw(self, id, password, acc_name, key):
        # Descargar la base de datos de las cuentas
        # Comprobar si existe id/password
        # Si existe buscamos la cuenta
        # Restamos el dinero
        # Si no, mandamos un warning
        pass

    def transfer(self, id, password, id2, acc_name, key, acc_name2):
        # Descargar la base de datos de las cuentas
        # Comprobar si existe id/password
        # Si existe buscamos la cuenta
        # Buscamos si existe id2
        # Transferimos el dinero
        # Si no, mandamos un warning
        pass

#En el futuro habrá métodos para quitar la redundancia de los métodos