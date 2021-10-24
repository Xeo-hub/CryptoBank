import os
import base64
from json_parser import JsonParser
from users import User
from accounts import Accounts
from user_storage import User_Storage
from account_storage import Account_Storage
from key_storage import Key_Storage
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

JSON_FILES_PATH = "C:/Users/Pablo/PycharmProjects/CryptoProject/JsonFiles/"
ACCOUNTS_PATH = JSON_FILES_PATH + "Accounts.json"
USERS_PATH = JSON_FILES_PATH + "Users.json"
MONEY_KEYS_PATH = JSON_FILES_PATH + "Money_Keys.json"


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

    def download_content_keys(self):
        key_storage = JsonParser(MONEY_KEYS_PATH)
        return key_storage.json_content

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
                    data = self.encrypt(b"0", b"money")
                    value = self.encode_to_string(data)
                    accounts_storage.add_item({str(temp): str(value)})
                    print("Cuenta creada")
                    return

    def modify_account(self, acc_name, key, new_key):
        user_store = User_Storage()
        account_store = Account_Storage()
        user_list = self.download_content_users()
        key_list = self.download_content_keys()
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
                                account_store.add_item({str(new_account): str(balance)})
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
        key_list = self.download_content_keys()
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
                                # Obtenemos el str que se almacena como dinero
                                str_value = account[id]
                                aad = b"money"
                                # Obtenemos la posición del elemento account
                                index = account_list.index(account)
                                # Sacamos la key y el nonce del elemento número "index" del fichero de claves
                                key = key_list[index][0]
                                nonce = key_list[index][1]
                                # Obtenemos los bytes al decodificar el ascii almacenado como dinero
                                encrypted_value = self.decode_to_bytes(str_value)
                                # Desencriptamos los bytes y obtenemos el valor entero
                                balance = self.decrypt(nonce, encrypted_value, aad, key)
                                account_store.delete_item(account)
                                balance += quantity
                                # Convertimos el entero a bytes para poder encriptarlo
                                bytes = self.int_to_bytes(balance)
                                # Encriptamos los bytes obtenidos
                                new_encrypted_value = self.encrypt(bytes, b"money")
                                # Convertimos los bytes en string para poder almacenarlo
                                value = self.encode_to_string(new_encrypted_value)
                                # Almacenamos el valor encriptado convertido a ascii
                                account_store.add_item({str(temp): str(value)})
                                print("Dinero ingresado")
                                return

    def withdraw(self, acc_name, key, quantity):
        account_store = Account_Storage()
        user_list = self.download_content_users()
        key_list = self.download_content_keys()
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
                                str_value = account[id]
                                aad = b"money"
                                # Sacamos la key y el nonce del elemento número "account" del fichero de claves
                                key = key_list[account][0]
                                nonce = key_list[account][1]
                                # Obtenemos los bytes al decodificar el ascii almacenado como dinero
                                encrypted_value = self.decode_to_bytes(str_value)
                                # Desencriptamos los bytes y obtenemos el valor entero
                                balance = self.decrypt(nonce, encrypted_value, aad, key)
                                balance -= quantity
                                # Convertimos el entero a bytes para poder encriptarlo
                                bytes = self.int_to_bytes(balance)
                                # Encriptamos los bytes obtenidos
                                new_encrypted_value = self.encrypt(bytes, b"money")
                                # Convertimos los bytes en string para poder almacenarlo
                                value = self.encode_to_string(new_encrypted_value)
                                # Almacenamos el valor encriptado convertido a ascii
                                if (balance < 0):
                                    print("Error: No dispone de tanto dinero en la cuenta")
                                    return
                                account_store.delete_item(account)
                                account_store.add_item({str(temp): str(value)})
                                print("Dinero sacado")
                                return
        print("Error: No existe ninguna cuenta con esos parámetros")

    def transfer(self, acc_name, key, id2, acc_name2, quantity):
        account_store = Account_Storage()
        user_list = self.download_content_users()
        key_list = self.download_content_keys()
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
                    str_value = account[id]
                    aad = b"money"
                    # Sacamos la key y el nonce del elemento número "account" del fichero de claves
                    key = key_list[account][0]
                    nonce = key_list[account][1]
                    # Obtenemos los bytes al decodificar el ascii almacenado como dinero
                    encrypted_value = self.decode_to_bytes(str_value)
                    # Desencriptamos los bytes y obtenemos el valor entero
                    balance = self.decrypt(nonce, encrypted_value, aad, key)
                    balance -= quantity
                    if (balance < 0):
                        print("Error: No dispone de tanto dinero en la cuenta")
                        return
                    # Convertimos el entero a bytes para poder encriptarlo
                    bytes = self.int_to_bytes(balance)
                    # Encriptamos los bytes obtenidos
                    new_encrypted_value = self.encrypt(bytes, b"money")
                    # Convertimos los bytes en string para poder almacenarlo
                    value = self.encode_to_string(new_encrypted_value)
                    # Almacenamos el valor encriptado convertido a ascii
                    account_store.delete_item(account)
                    account_store.add_item({str(temp): str(value)})
                    cond += 1

                if (id.find(sec_user_account) == 0):
                    str_value = account[id]
                    aad = b"money"
                    # Sacamos la key y el nonce del elemento número "account" del fichero de claves
                    key = key_list[account][0]
                    nonce = key_list[account][1]
                    # Obtenemos los bytes al decodificar el ascii almacenado como dinero
                    encrypted_value = self.decode_to_bytes(str_value)
                    # Desencriptamos los bytes y obtenemos el valor entero
                    balance = self.decrypt(nonce, encrypted_value, aad, key)
                    balance += quantity
                    account_store.delete_item(account)
                    bytes = self.int_to_bytes(balance)
                    # Encriptamos los bytes obtenidos
                    new_encrypted_value = self.encrypt(bytes, b"money")
                    # Convertimos los bytes en string para poder almacenarlo
                    value = self.encode_to_string(new_encrypted_value)
                    # Almacenamos el valor encriptado convertido a ascii
                    account_store.add_item({id: str(value)})
                    cond += 1

                if (cond == 2):
                    break

    def sign_out(self):
        # Cerramos sesión
        self.sign_up = False
        return

    @staticmethod
    def encode_to_string(bytes_key):
        b64_bytes_key = base64.urlsafe_b64encode(bytes_key)
        b64_string_key = b64_bytes_key.decode("ascii")
        return b64_string_key


    def decode_to_bytes(self, b64_bytes_key_bis):
        bytes_key_bis = base64.urlsafe_b64decode(b64_bytes_key_bis)
        b64_string_key = bytes_key_bis.decode("ascii")
        return b64_string_key


    def encrypt(self,data, aad):
        key_storage = Key_Storage()
        key = AESGCM.generate_key(bit_length=128)
        #ALMACENAR KEY EN FICHERO JSON CLAVES
        aesgcm = AESGCM(key)
        #ALMACENAR NONCE EN FICHERO JSON CLAVES
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, data, aad)
        str_key = self.encode_to_string(key)
        str_nonce = self.encode_to_string(nonce)
        key_storage.add_item([str_key, str_nonce])
        return ct

    def decrypt(self, nonce, data, aad, key):
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, data, aad)

    def int_to_bytes(self, x: int) -> bytes:
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')

    def int_from_bytes(self, xbytes: bytes) -> int:
        return int.from_bytes(xbytes, 'big')

    def sign_out(self):
        # Cerramos sesión
        self.sign_up = False
        return