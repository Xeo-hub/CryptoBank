from json_parser import JsonParser
from users import User
from accounts import Accounts
from user_storage import User_Storage
from account_storage import Account_Storage

JSON_FILES_PATH = "D:/PyCharm/Proyectos/CryptoProject/JsonFiles/"
ACCOUNTS_PATH = JSON_FILES_PATH + "Accounts.json"
USERS_PATH = JSON_FILES_PATH + "Users.json"



class CryptoBank:
    sign_up = False
    current_user = None

    def download_content_users(self):
        # Sacamos los datos de los usuarios
        accounts_storage = JsonParser(USERS_PATH)
        return accounts_storage.json_content

    def download_content_accounts(self):
        # Sacamos los datos de las cuentas
        accounts_storage = JsonParser(ACCOUNTS_PATH)
        return accounts_storage.json_content

    def login(self, id, password):
        # Para iniciar sesión
        # Cargamos a todos los usarios
        user_list = self.download_content_users()
        user = User(id, password)
        # Buscamos al usuario en la lista de usuarios
        for item in user_list:
            for key in item:
                if key == str(user):
                    # Si coincide existe e inicias la sesión
                    print("Sesion iniciada")
                    self.sign_up = True
                    self.current_user = User(id, password)
                    return
        # Si no existe
        print("Error: Usuario o contraseña incorrectos")
        return

    def new_user_account(self, id, password):
        # Para crear cuenta
        user_store = User_Storage()
        user_list = self.download_content_users()
        user = User(id, password)
        # Buscamos que no exista ya uno con el mismo nombre
        for item in user_list:
            for key in item:
                if key.find(user.user) == 0:
                    print("Error: Ya existe un usuario con este nombre")
                    return
        # Si no, se crea
        print("Usuario creado")
        self.sign_up = True
        self.current_user = User(id, password)
        user_store.add_item({str(self.current_user): []})
        return

    def create_account(self, acc_name, key): #TODO no crear cuentas con el mismo acc_name en el mismo user
        # Buscamos al user
        user_store = User_Storage()
        user_list = self.download_content_users()
        for user in user_list:
            for id in user:
                # Buscamos su cuenta
                if id == str(self.current_user):
                    temp = Accounts(acc_name, key)
                    # Si ya tiene una igual no la creamos
                    if (str(temp) in user[id]):
                        print("Error: Cuenta ya existente")
                        return
                    # La creamos y actualizamos
                    user_store.delete_item(user)
                    user[id].append(str(temp))
                    user_store.add_item(user)
                    # La añadimos al fichero de cuentas
                    accounts_storage = Account_Storage()
                    # Quizá encriptar con el user para que no se repita o algo para que no haya repetición
                    accounts_storage.add_item({str(temp):0})
                    print("Cuenta creada")
                    return

    def modify_account(self, acc_name, key, new_key):
        user_store = User_Storage()
        account_store = Account_Storage()
        user_list = self.download_content_users()
        # Buscamos el user
        for user in user_list:
            for id in user:
                # Si existe modificamos la cuenta
                if id == str(self.current_user):
                    new_account = Accounts(acc_name, new_key)
                    temp = Accounts(acc_name, key)
                    if (str(temp) not in user[id]):
                        print("Error: No existe la cuenta a modificar")
                        return
                    if (str(new_account) in user[id]):
                        print("Error: Intentas modificar a una cuenta ya existente")
                        return
                    # Actualizamos
                    user_store.delete_item(user)
                    user[id].remove(str(temp))
                    user[id].append(str(new_account))
                    user_store.add_item(user)
                    # La modificamos en el fichero de cuentas
                    account_list = self.download_content_accounts()
                    # Quizá encriptar con el user para que no se repita o algo para que no haya repetición
                    for user in account_list:
                        for id in user:
                            if id == str(temp):
                                balance = user[id]
                                account_store.delete_item(user)
                                account_store.add_item({str(new_account): balance})
                                print("Cuenta modificada")
                                return

    def delete_account(self, acc_name, key):
        user_storage = User_Storage()
        account_store = Account_Storage()
        user_list = self.download_content_users()
        # Buscamos el user
        for user in user_list:
            for id in user:
                # Si existe la borramos
                if id == str(self.current_user):
                    if (len(user[id]) == 0):
                        print("Error: No existen cuentas para este usuario")
                        return

                    temp = Accounts(acc_name, key)
                    if (str(temp) not in user[id]):
                        print("Error: No existe la cuenta a borrar")
                        return
                    # Actualizamos
                    user_storage.delete_item(user)
                    user[id].remove(str(temp))
                    user_storage.add_item(user)
                    # Actualizamos en el fichero de cuentas
                    account_list = self.download_content_accounts()
                    for user in account_list:
                        for id in user:
                            if id == str(temp):
                                account_store.delete_item(user)
                    print("Cuenta eliminada")
                    return


    def deposit(self, acc_name, key, quantity):
        account_store = Account_Storage()
        user_list = self.download_content_users()
        # Buscamos el user
        for user in user_list:
            for id in user:
                if id == str(self.current_user):
                    temp = Accounts(acc_name, key)
                    if (str(temp) not in user[id]):
                        print("Error: No existe la cuenta a ingresar")
                        return
                    # Buscamos la cuenta
                    account_list = self.download_content_accounts()
                    for account in account_list:
                        for id in account:
                            if id == str(temp):
                                # Sumamos el dinero
                                balance = account[id]
                                account_store.delete_item(account)
                                balance += quantity
                                account_store.add_item({str(temp): balance})
                                print("Dinero ingresado")
                                return

    def withdraw(self, acc_name, key, quantity):
        account_store = Account_Storage()
        user_list = self.download_content_users()
        # Buscamos el user
        for user in user_list:
            for id in user:
                if id == str(self.current_user):
                    temp = Accounts(acc_name, key)
                    if (str(temp) not in user[id]):
                        print("Error: No existe la cuenta a sacar")
                        return
                    # Buscamos la cuenta
                    account_list = self.download_content_accounts()
                    for account in account_list:
                        for id in account:
                            if id == str(temp):
                                # Sacamos el dinero
                                balance = account[id]
                                balance -= quantity
                                if (balance < 0):
                                    print("Error: No dispone de tanto dinero en la cuenta")
                                    return
                                account_store.delete_item(account)
                                account_store.add_item({str(temp): balance})
                                print("Dinero sacado")
                                return
        print("Error: No existe ninguna cuenta con esos parámetros")

    def transfer(self, acc_name, key, id2, acc_name2, quantity):
        account_store = Account_Storage()
        user_list = self.download_content_users()
        temp = None
        cond = 0
        # Buscamos a los dos users
        for user in user_list:
            for id in user:
                # Buscamos la cuenta
                if id == str(self.current_user):
                    if (len(user[id]) == 0):
                        print("Error: No existen cuentas para este usuario")
                        return

                    temp = Accounts(acc_name, key)
                    if (str(temp) not in user[id]):
                        print("Error: No existe cuenta de la que transferir dinero")
                        return
                    cond += 1
                # Segundo user
                if id.find(id2) == 0:
                    sec_user = user
                    cond += 1
            if (cond == 2):
                break
        # No existe la cuenta
        if (temp is None):
            print("Error: No existe ninguna cuenta con esos parámetros")
            return

        if(cond == 1):
            print("Error: No existe el destinatario")
            return

        # Buscamos la cuenta a la que transferir
        sec_user_account = None
        for id in sec_user:
            for account in sec_user[id]:
                if account.find(acc_name2) == 0:
                    sec_user_account = account

        # Si no existe
        if (sec_user_account is None):
            print("Error: El destinatario no tiene una cuenta con ese parámetro")
            return

        # Hacemos la transferencia
        account_list = self.download_content_accounts()
        cond = 0
        # Quizá encriptar con el user para que no se repita o algo para que no haya repetición
        for account in account_list:
            for id in account:
                if id == str(temp):
                    balance = account[id]
                    balance -= quantity
                    if (balance < 0):
                        print("Error: No dispone de tanto dinero en la cuenta")
                        return
                    account_store.delete_item(account)
                    account_store.add_item({str(temp): balance})
                    cond += 1

                if (id.find(sec_user_account) == 0):
                    balance = account[id]
                    balance += quantity
                    account_store.delete_item(account)
                    account_store.add_item({id: balance})
                    cond += 1

                if (cond == 2):
                    break



    def sign_out(self):
        # Cerramos sesión
        self.sign_up = False
        return
