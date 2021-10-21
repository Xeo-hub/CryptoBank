JSON_FILES_PATH = "D:/PyCharm/Proyectos/CryptoProject/JsonFiles/"
from json_storage import JsonStore
print(JSON_FILES_PATH)

from users import User
from json_storage import JsonStore

class CryptoBank:
    def create_account(self, id, password, acc_name, key):
        user = User(id, password)
        accounts_storage = JsonStore()
        accounts=accounts_storage.load_store()
        account=self.verify(user)
        # Comprobar si existe id/password
        # Si no, se crea de 0
        # Cifrar acc_name y key (esto puede)
        if account==None:
            accounts.add_item(user)
        # Si existe se le mete en la cuenta


    def login(self, id, password):
        self.verify (id, password)
        print("Sesion iniciada")


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
                return user
        print("Error")
        return None


    def delete_account(self, id, password, acc_name, key):
        # Descargar la base de datos de las cuentas
        # Comprobar si existe id/password
        # Cifrar acc_name y key
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
        # Ciframos acc_name key
        # Si existe buscamos la cuenta
        # Sumamos el dinero
        # Si no, mandamos un warning
        pass

    def withdraw(self, id, password, acc_name, key):
        # Descargar la base de datos de las cuentas
        # Comprobar si existe id/password
        # Ciframos acc_name key
        # Autenticamos
        # Si existe buscamos la cuenta
        # Restamos el dinero
        # Si no, mandamos un warning
        pass

    def transfer(self, id, password, id2, acc_name, key, acc_name2):
        # Descargar la base de datos de las cuentas
        # Comprobar si existe id/password
        # Ciframos acc_name key y acc_name2
        # Autenticamos
        # Si existe buscamos la cuenta
        # Buscamos si existe id2
        # Firma digital
        # Transferimos el dinero
        # Si no, mandamos un warning
        pass

#En el futuro habrá métodos para quitar la redundancia de los métodos