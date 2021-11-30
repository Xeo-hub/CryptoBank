import os
import base64
from datetime import datetime

from cryptography.exceptions import InvalidTag, InvalidKey, InvalidSignature

from json_parser import JsonParser
from users import User
from accounts import Accounts
from user_storage import User_Storage
from account_storage import Account_Storage
from key_storage import Key_Storage
from user_salt_storage import User_Salt_Storage
from account_salt_storage import Account_Salt_Storage
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives import hashes


#JSON_FILES_PATH = "C:/Users/madrid/PycharmProjects/CryptoProject/JsonFiles/"
# JSON_FILES_PATH = "C:\Users\Pablo\PycharmProjects\CryptoProject\JsonFiles\"
JSON_FILES_PATH = "D:/PyCharm/Proyectos/CryptoProject2/JsonFiles/"
ACCOUNTS_PATH = JSON_FILES_PATH + "Accounts.json"
USERS_PATH = JSON_FILES_PATH + "Users.json"
MONEY_KEYS_PATH = JSON_FILES_PATH + "Money_Keys.json"
USER_SALT_PATH = JSON_FILES_PATH + "User_salt.json"
ACCOUNT_SALT_PATH = JSON_FILES_PATH + "Account_salt.json"


class CryptoBank:
    sign_up = 0
    current_user = None
    current_account = None
    __master_key = ""
    __master_nonce = ""

    @property
    def master_key(self):
        if self.current_user != None:
            return self.__master_key
        print("Intento de acceso al sistema\nSe procede a cerrar el sistema")
        exit(-2)

    @master_key.setter
    def master_key(self, otro):
        if (self.__master_key == ""):
            self.__master_key = otro
        else:
            print("Intento de acceso al sistema\nSe procede a cerrar el sistema")
            exit(-2)

    @property
    def master_nonce(self):
        if self.current_user != None:
            return self.__master_nonce
        print("Intento de acceso al sistema\nSe procede a cerrar el sistema")
        exit(-2)

    @master_nonce.setter
    def master_nonce(self, otro):
        if (self.__master_nonce == ""):
            self.__master_nonce = otro
        else:
            print("Intento de acceso al sistema\nSe procede a cerrar el sistema")
            exit(-2)

    def download_content_users(self):
        # Sacamos los datos de los usuarios
        accounts_storage = JsonParser(USERS_PATH)
        return accounts_storage.json_content

    def download_content_accounts(self):
        # Sacamos los datos de las cuentas
        accounts_storage = JsonParser(ACCOUNTS_PATH)
        return accounts_storage.json_content

    def download_content_keys(self):
        # Sacamos los datos de las keys
        key_storage = JsonParser(MONEY_KEYS_PATH)
        return key_storage.json_content

    def download_content_user_salt(self):
        # Sacamos los datos del scrypt
        scrypt_storage = JsonParser(USER_SALT_PATH)
        return scrypt_storage.json_content

    def download_content_account_salt(self):
        # Sacamos los datos del scrypt
        scrypt_storage = JsonParser(ACCOUNT_SALT_PATH)
        return scrypt_storage.json_content

    def login(self, id, password):
        # Para iniciar sesión
        # Cargamos a todos los usarios
        user_list = self.download_content_users()
        scrypt_list = self.download_content_user_salt()
        # Buscamos al usuario en la lista de usuarios
        for item in user_list:
            for key in item:
                if key.find(id) == 0:
                    index = user_list.index(item)
                    # Nos quedamos con el salt asociado al usuario correspondiente
                    str_encrypted_salt = scrypt_list[index]
                    # Pasamos el salt a bytes
                    encrypted_salt = self.decode_to_bytes(str_encrypted_salt)
                    # Desencriptamos el salt
                    stored_key = self.get_after_slice(key)
                    self.sign_up = 1
                    self.current_user = User(id, stored_key)
                    try:
                        salt = self.decrypt_with_master_key(encrypted_salt, self.master_key, self.master_nonce)
                    except InvalidTag:
                        print("Acceso no permitido al sistema")
                        exit(-2)
                    # Comparamos la key almacenada con la password introducida y el salt almacenado
                    scrypt_password = password.encode('ascii')
                    stored_key = self.decode_to_bytes(stored_key)
                    try:
                        self.scrypt_verify(scrypt_password, salt, stored_key)
                    except InvalidKey:
                        self.sign_up = 0
                        self.current_user = None
                        print("Contraseña incorrecta")
                        return
                    # Si coincide existe e inicias la sesión
                    print("Sesion iniciada")

                    return
        # Si no existe
        print("Error: Usuario o contraseña incorrectos")
        return

    def new_user_account(self, id, password):
        # Para crear cuenta
        user_store = User_Storage()
        user_list = self.download_content_users()

        # Buscamos que no exista ya uno con el mismo nombre
        for item in user_list:
            for key in item:
                if key.find(id) == 0:
                    print("Error: Ya existe un usuario con este nombre")
                    return

        # Si no, se crea
        # Creamos el objeto de almacenaje para poder integrar el nuevo salt en el json
        scrypt_store = User_Salt_Storage()
        # Generamos un salt para cifrar la contraseña
        salt = os.urandom(16)
        # Pasamos a bytes la password para poder utilizarla como mensaje

        # Encriptamos la password
        scrypt_password = self.scrypt_encrypt(password, salt)
        scrypt_password = self.encode_to_string(scrypt_password)
        self.sign_up = 1
        self.current_user = User(id, scrypt_password)
        # Ciframos el salt con los parámetros master
        encrypted_salt = self.encrypt_with_master_key(salt, self.master_key, self.master_nonce)
        str_encrypted_salt = self.encode_to_string(encrypted_salt)
        scrypt_store.add_item(str_encrypted_salt)
        print("Usuario creado")
        user_store.add_item({str(self.current_user): []})
        return

    def create_account(self, acc_name, key):
        # Buscamos al user
        user_store = User_Storage()
        user_list = self.download_content_users()
        scrypt_account_store = Account_Salt_Storage()
        scrypt_user_store = User_Salt_Storage()
        scrypt_user_list = self.download_content_user_salt()
        for user in user_list:
            for id in user:
                # Buscamos su cuenta
                if id == str(self.current_user):
                    salt = os.urandom(16)
                    scrypt_key = self.scrypt_encrypt(key, salt)
                    encrypted_scrypt_salt = self.encrypt_with_master_key(salt, self.master_key, self.master_nonce)
                    encr_salt_xor_key = self.xor(encrypted_scrypt_salt, key.encode('ascii'))
                    scrypt_key = self.encode_to_string(scrypt_key)

                    temp = Accounts(acc_name, scrypt_key)
                    # Si ya tiene una igual no la creamos
                    for account in user[id]:
                        if acc_name in self.get_before_slice(account):
                            print("Error: Ya existe una cuenta con ese nombre")
                            return
                    scrypt_account_store.add_item(self.encode_to_string(encr_salt_xor_key))

                    # La creamos y actualizamos
                    user_store.delete_item(user)
                    user[id].append(str(temp))
                    user_store.add_item(user)
                    # La añadimos al fichero de cuentas
                    accounts_storage = Account_Storage()
                    initial_money = 0
                    money_bytes = self.int_to_bytes(initial_money)
                    data = self.encrypt(money_bytes, b"money")
                    value = self.encode_to_string(data)
                    accounts_storage.add_item({str(temp): str(value)})
                    index = user_list.index(user)
                    scrypt = scrypt_user_list[index]
                    scrypt_user_store.delete_item(scrypt)
                    scrypt_user_store.add_item(scrypt)
                    print("Cuenta creada")
                    self.current_account = temp
                    self.sign_up = 2
                    return

    def access_account(self, acc_name, key):
        user_list = self.download_content_users()
        scrypt_list = self.download_content_account_salt()
        # Buscamos el user
        for user in user_list:
            for id in user:
                # Si existe la borramos
                if id == str(self.current_user):
                    if (len(user[id]) == 0):
                        print("Error: No existen cuentas para este usuario")
                        return
                    # Depende de como lo vayamos a almacenar

                    cond = 0
                    for account in user[id]:
                        stored_acc_name = self.get_before_slice(account)
                        if (stored_acc_name == acc_name):
                            cond = 1
                            break
                    if (cond == 0):
                        print("Nombre de cuenta incorrecto")
                        return


                    # Como sea obtienes el salt
                    cond = 0
                    for account_salt in scrypt_list:
                        encr_salt_xor_key = self.decode_to_bytes(account_salt)
                        encr_salt = self.xor(encr_salt_xor_key, key.encode('ascii'))
                        try:
                            salt = self.decrypt_with_master_key(encr_salt, self.master_key, self.master_nonce)
                            # Comparamos la key almacenada con la password introducida y el salt almacenado
                            stored_key = self.get_after_slice(account)
                            stored_key = self.decode_to_bytes(stored_key)
                            self.scrypt_verify(key.encode('ascii'), salt, stored_key)
                            cond = 1
                            break
                        except:
                            continue
                    if (cond == 0):
                        print("Clave incorrecta")
                        return


                    temp = Accounts(acc_name, self.encode_to_string(stored_key))
                    self.current_account = temp
                    self.sign_up = 2
                    print("Accedido a cuenta")
                    return
        print("No existe la cuenta a la que intentas acceder")

    def modify_account(self, acc_name,key, new_key):
        user_store = User_Storage()
        account_store = Account_Storage()
        user_list = self.download_content_users()
        scrypt_user_store = User_Salt_Storage()
        scrypt_user_list = self.download_content_user_salt()
        scrypt_account_list = self.download_content_account_salt()
        scrypt_account_store = Account_Salt_Storage()
        # Buscamos el user
        for user in user_list:
            for id in user:
                # Si existe modificamos la cuenta
                if id == str(self.current_user):
                    cond = 0
                    for account in user[id]:
                        stored_acc_name = self.get_before_slice(account)
                        if (stored_acc_name == acc_name):
                            cond = 1
                            break
                    if (cond == 0):
                        print("Nombre de cuenta incorrecto")
                        return
                    cond = 0
                    for account_salt in scrypt_account_list:
                        encr_salt_xor_key = self.decode_to_bytes(account_salt)
                        encr_salt = self.xor(encr_salt_xor_key, key.encode('ascii'))
                        try:
                            salt = self.decrypt_with_master_key(encr_salt, self.master_key, self.master_nonce)
                            # Comparamos la key almacenada con la password introducida y el salt almacenado
                            stored_key = self.get_after_slice(str(self.current_account))
                            stored_key = self.decode_to_bytes(stored_key)
                            self.scrypt_verify(key.encode('ascii'), salt, stored_key)
                            cond = 1
                            break
                        except:
                            continue
                    if (cond == 0):
                        print("Clave original incorrecta")
                        return
                    scrypt_account_store.delete_item(account_salt)
                    #Generamos el nuevo scrypt para la nueva clave
                    salt = os.urandom(16)
                    scrypt_key = self.scrypt_encrypt(new_key, salt)
                    encrypted_scrypt_salt = self.encrypt_with_master_key(salt, self.master_key, self.master_nonce)
                    encr_salt_xor_key = self.xor(encrypted_scrypt_salt, new_key.encode('ascii'))
                    scrypt_account_store.add_item(self.encode_to_string(encr_salt_xor_key))
                    new_key_scrypted = self.encode_to_string(scrypt_key)

                    new_account = Accounts(acc_name, new_key_scrypted)
                    if (str(new_account) in user[id]):
                        print("Error: Intentas modificar a una cuenta ya existente")
                        return
                    # Actualizamos
                    user_store.delete_item(user)
                    user[id].remove(str(self.current_account))
                    user[id].append(str(new_account))
                    user_store.add_item(user)
                    index = user_list.index(user)
                    scrypt = scrypt_user_list[index]
                    scrypt_user_store.delete_item(scrypt)
                    scrypt_user_store.add_item(scrypt)
                    # La modificamos en el fichero de cuentas
                    account_list = self.download_content_accounts()
                    for user in account_list:
                        for id in user:
                            if id == str(self.current_account):
                                balance = user[id]
                                account_store.delete_item(user)
                                account_store.add_item({str(new_account): str(balance)})
                                self.current_account = new_account
                                print("Cuenta modificada")
                                return

    def delete_account(self, key):
        user_storage = User_Storage()
        key_store = Key_Storage()
        account_store = Account_Storage()
        user_list = self.download_content_users()
        scrypt_user_store = User_Salt_Storage()
        scrypt_user_list = self.download_content_user_salt()
        scrypt_account_store = Account_Salt_Storage()
        scrypt_account_list = self.download_content_account_salt()
        # Buscamos el user
        for user in user_list:
            for id in user:
                # Si existe la borramos
                if id == str(self.current_user):
                    if (len(user[id]) == 0):
                        print("Error: No existen cuentas para este usuario")
                        return
                    # Actualizamos
                    user_storage.delete_item(user)
                    user[id].remove(str(self.current_account))
                    user_storage.add_item(user)
                    index = user_list.index(user)
                    scrypt = scrypt_user_list[index]
                    scrypt_user_store.delete_item(scrypt)
                    scrypt_user_store.add_item(scrypt)
                    cond = 0
                    for account_salt in scrypt_account_list:
                        encr_salt_xor_key = self.decode_to_bytes(account_salt)
                        encr_salt = self.xor(encr_salt_xor_key, key.encode('ascii'))
                        try:
                            salt = self.decrypt_with_master_key(encr_salt, self.master_key, self.master_nonce)
                            # Comparamos la key almacenada con la password introducida y el salt almacenado
                            stored_key = self.get_after_slice(str(self.current_account))
                            stored_key = self.decode_to_bytes(stored_key)
                            self.scrypt_verify(key.encode('ascii'), salt, stored_key)
                            cond = 1
                            break
                        except:
                            continue
                    if (cond == 0):
                        print("Clave original incorrecta")
                        return
                    scrypt_account_store.delete_item(account_salt)
                    # Actualizamos en el fichero de cuentas
                    account_list = self.download_content_accounts()
                    key_list = self.download_content_keys()
                    for user in account_list:
                        for id in user:
                            if id == str(self.current_account):
                                # Obtenemos la posición del elemento account
                                index = account_list.index(user)
                                account_store.delete_item(user)
                                # Sacamos la key y el nonce del elemento número "account" del fichero de claves
                                key = key_list[index][0]
                                nonce = key_list[index][1]
                                key_store.delete_item([key, nonce])
                    self.sign_up = 1
                    self.current_account = None
                    print("Cuenta eliminada")
                    return

    def deposit(self, quantity):
        account_store = Account_Storage()
        key_store = Key_Storage()
        user_list = self.download_content_users()
        key_list = self.download_content_keys()
        # Buscamos el user
        for user in user_list:
            for id in user:
                if id == str(self.current_user):
                    # Buscamos la cuenta
                    account_list = self.download_content_accounts()
                    for account in account_list:
                        for id in account:
                            if id == str(self.current_account):
                                # Obtenemos el str que se almacena como dinero
                                str_value = account[id]
                                aad = b"money"
                                # Obtenemos la posición del elemento account
                                index = account_list.index(account)
                                # Sacamos la key y el nonce del elemento número "index" del fichero de claves
                                key = key_list[index][0]
                                nonce = key_list[index][1]
                                key_store.delete_item([key,nonce])
                                # Obtenemos los bytes al decodificar el ascii almacenado como dinero
                                encrypted_value = self.decode_to_bytes(str_value)
                                key_bytes = key.encode('ascii')
                                nonce_bytes = nonce.encode('ascii')
                                # Desencriptamos los bytes y obtenemos el valor entero
                                try:
                                    balance = self.decrypt(nonce_bytes, encrypted_value, aad, key_bytes)
                                except InvalidTag:
                                    print("Error: Los datos han sido modificiados por un externo")
                                    exit(-3)
                                balance = self.int_from_bytes(balance)
                                balance += quantity
                                # Convertimos el entero a bytes para poder encriptarlo
                                bytes = self.int_to_bytes(balance)
                                # Encriptamos los bytes obtenidos
                                new_encrypted_value = self.encrypt(bytes, aad)
                                # Convertimos los bytes en string para poder almacenarlo
                                value = self.encode_to_string(new_encrypted_value)
                                # Almacenamos el valor encriptado convertido a ascii
                                account_store.delete_item(account)
                                account_store.add_item({str(self.current_account): str(value)})
                                print("Dinero ingresado")
                                return

    def withdraw(self, quantity):
        account_store = Account_Storage()
        key_store = Key_Storage()
        user_list = self.download_content_users()
        key_list = self.download_content_keys()
        # Buscamos el user
        for user in user_list:
            for id in user:
                if id == str(self.current_user):
                    # Buscamos la cuenta
                    account_list = self.download_content_accounts()
                    for account in account_list:
                        for id in account:
                            if id == str(self.current_account):
                                # Sacamos el dinero
                                str_value = account[id]
                                aad = b"money"
                                # Obtenemos la posición del elemento account
                                index = account_list.index(account)
                                # Sacamos la key y el nonce del elemento número "account" del fichero de claves
                                key = key_list[index][0]
                                nonce = key_list[index][1]
                                # Obtenemos los bytes al decodificar el ascii almacenado como dinero
                                encrypted_value = self.decode_to_bytes(str_value)
                                # Desencriptamos los bytes y obtenemos el valor entero
                                key_bytes = key.encode('ascii')
                                nonce_bytes = nonce.encode('ascii')
                                try:
                                    balance = self.decrypt(nonce_bytes, encrypted_value, aad, key_bytes)
                                except InvalidTag:
                                    print("Error: Los datos han sido modificados por un tercero")
                                    exit(-3)

                                balance = self.int_from_bytes(balance)
                                balance -= quantity
                                # Almacenamos el valor encriptado convertido a ascii
                                if balance < 0:
                                    print("Error: No dispone de tanto dinero en la cuenta")
                                    return
                                key_store.delete_item([key,nonce])
                                # Convertimos el entero a bytes para poder encriptarlo
                                bytes = self.int_to_bytes(balance)
                                # Encriptamos los bytes obtenidos
                                new_encrypted_value = self.encrypt(bytes, aad)
                                # Convertimos los bytes en string para poder almacenarlo
                                value = self.encode_to_string(new_encrypted_value)

                                # Generamos texto firmado por el banco sobre que se ha sacado dinero
                                now_date = datetime.utcnow()
                                # Obtenemos clave privada
                                file = open("JsonFiles/private_key.json", "rb")
                                private_key = file.read()
                                private_key = self.decode_to_bytes(private_key)
                                # Deserializamos clave privada
                                try:
                                    private_key_deserializated = serialization.load_pem_private_key(private_key, b'elbicho64')
                                except ValueError:
                                    print("El PEM no se ha podido desencriptar correctamente")
                                    exit(-3)
                                except TypeError:
                                    print("La password tiene un formato incorrecto")
                                    exit(-3)

                                # Generamos mensaje
                                message = "Usuario: " + str(self.current_user.user) + "\nCantidad: " + str(quantity) + " euros\nFecha: " + str(now_date)
                                # Firmamos mensaje
                                message = message.encode('ascii')
                                signature = self.sign_message(message, private_key_deserializated)
                                str_signature = self.encode_to_string(signature)
                                signature_file = open("JsonFiles/signature_" + str(self.current_account.acc_name) + ".json", "w")
                                # Guardamos firma en fichero
                                signature_file.write(str_signature)
                                message_file = open("JsonFiles/message_" + str(self.current_account.acc_name) + ".json", "w")
                                # Guardamos mensaje en fichero
                                message_file.write(message.decode('ascii'))
                                # Verificamos que el mensaje esta bien firmado con los certificados
                                # Obtenemos clave publica
                                public_key_deserializated = private_key_deserializated.public_key()
                                # Verificamos con RSA
                                try:
                                    self.verify_message(public_key_deserializated, signature, message)
                                except InvalidSignature:
                                    print("La firma no coincide con la clave RSA")
                                    exit(-3)
                                # Generamos los certificados para las verificaciones
                                # Obtenemos certificado AC1
                                ac1_fd = open("certificates/ac1cert.pem", "rb")
                                ac1 = self.get_authority(ac1_fd)
                                # Obtenemos certificado CryptoBank
                                cryptobank_fd = open("certificates/01.pem", "rb")
                                cryptobank = self.get_authority(cryptobank_fd)
                                # Comprobamos si la clave publica del mensaje se corresponde con la del certificado de CryptoBank
                                try:
                                    self.verify_message(cryptobank.public_key(), signature, message)
                                except InvalidSignature:
                                    print("La firma no coincide con la clave del certificado")
                                    exit(-3)
                                # Verificamos certificado de CryptoBank con autoridad raiz
                                try:
                                    self.verify_certificate(cryptobank, ac1)
                                except InvalidSignature:
                                    print("El certificado cryptobank no es fiable")
                                    exit(-3)
                                # Verificamos autoridad raiz consigo misma
                                try:
                                    self.verify_certificate(ac1, ac1)
                                except InvalidSignature:
                                    print("La autoridad de certificación no es fiable")
                                    exit(-3)
                                account_store.delete_item(account)
                                account_store.add_item({str(self.current_account): str(value)})
                                print("Dinero sacado")
                                return


    def transfer(self, id2, acc_name2, quantity):
        account_store = Account_Storage()
        key_store = Key_Storage()
        user_list = self.download_content_users()
        key_list = self.download_content_keys()
        cond = 0
        # Buscamos a los dos users
        for user in user_list:
            for id in user:
                # Buscamos la cuenta
                if id == str(self.current_user):
                    if (len(user[id]) == 0):
                        print("Error: No existen cuentas para este usuario")
                        return
                    cond += 1
                # Segundo user
                if id.find(id2) == 0:
                    sec_user = user
                    cond += 1
            if (cond == 2):
                break

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
        able = False
        for account in account_list:
            for id in account:
                if id == str(self.current_account):
                    str_value = account[id]
                    aad = b"money"
                    # Obtenemos la posición del elemento account
                    index = account_list.index(account)
                    # Sacamos la key y el nonce del elemento número "account" del fichero de claves
                    key = key_list[index][0]
                    nonce = key_list[index][1]
                    # Obtenemos los bytes al decodificar el ascii almacenado como dinero
                    encrypted_value = self.decode_to_bytes(str_value)
                    key_bytes = key.encode('ascii')
                    nonce_bytes = nonce.encode('ascii')
                    # Desencriptamos los bytes y obtenemos el valor entero
                    try:
                        balance = self.decrypt(nonce_bytes, encrypted_value, aad, key_bytes)
                    except InvalidTag:
                        print("Error: Los datos han sido modificados por un tercero")
                        exit(-3)
                    balance = self.int_from_bytes(balance)
                    balance -= quantity
                    if (balance < 0):
                        print("Error: No dispone de tanto dinero en la cuenta")
                        return
                    able = True
                    key_store.delete_item([key,nonce])
                    # Convertimos el entero a bytes para poder encriptarlo
                    bytes = self.int_to_bytes(balance)
                    # Encriptamos los bytes obtenidos
                    new_encrypted_value = self.encrypt(bytes, aad)
                    # Convertimos los bytes en string para poder almacenarlo
                    value = self.encode_to_string(new_encrypted_value)
                    # Almacenamos el valor encriptado convertido a ascii
                    account_store.delete_item(account)
                    account_store.add_item({str(self.current_account): str(value)})
                    break

        if (able):
            for account in account_list:
                for id in account:
                    if (id.find(sec_user_account) == 0):
                        str_value = account[id]
                        aad = b"money"
                        # Obtenemos la posición del elemento account
                        index = account_list.index(account)
                        # Sacamos la key y el nonce del elemento número "account" del fichero de claves
                        key = key_list[index][0]
                        nonce = key_list[index][1]
                        # Obtenemos los bytes al decodificar el ascii almacenado como dinero
                        encrypted_value = self.decode_to_bytes(str_value)
                        key_bytes = key.encode('ascii')
                        nonce_bytes = nonce.encode('ascii')
                        # Desencriptamos los bytes y obtenemos el valor entero
                        try:
                            balance = self.decrypt(nonce_bytes, encrypted_value, aad, key_bytes)
                        except InvalidTag:
                            print("Error: Los datos han sido modificados por un tercero")
                            exit(-3)
                        balance = self.int_from_bytes(balance)
                        balance += quantity
                        key_store.delete_item([key,nonce])
                        account_store.delete_item(account)
                        bytes = self.int_to_bytes(balance)
                        # Encriptamos los bytes obtenidos
                        new_encrypted_value = self.encrypt(bytes, aad)
                        # Convertimos los bytes en string para poder almacenarlo
                        value = self.encode_to_string(new_encrypted_value)
                        # Almacenamos el valor encriptado convertido a ascii
                        account_store.add_item({id: str(value)})
                        break

        print("Transferencia realizada")

    def check_balance(self):
        user_list = self.download_content_users()
        key_list = self.download_content_keys()
        # Buscamos el user
        for user in user_list:
            for id in user:
                if id == str(self.current_user):
                    # Buscamos la cuenta
                    account_list = self.download_content_accounts()
                    for account in account_list:
                        for id in account:
                            if id == str(self.current_account):
                                # Sacamos el dinero
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
                                try:
                                    balance = self.decrypt(nonce, encrypted_value, aad, key)
                                except InvalidTag:
                                    print("Error: Los datos han sido modificados por un tercero")
                                    exit(-3)
                                balance = self.int_from_bytes(balance)
                                print("Dispone de " + str(balance) + "€ en su cuenta")

    def log_out(self):
        # Cerramos sesión
        self.sign_up = 1
        self.current_account = None
        return

    @staticmethod
    def encode_to_string(bytes_key):
        b64_bytes_key = base64.urlsafe_b64encode(bytes_key)
        b64_string_key = b64_bytes_key.decode("ascii")
        return b64_string_key


    def decode_to_bytes(self, b64_bytes_key_bis):
        bytes_key_bis = base64.urlsafe_b64decode(b64_bytes_key_bis)
        return bytes_key_bis


    def encrypt(self,data, aad):
        key_storage = Key_Storage()
        key = AESGCM.generate_key(bit_length=256) #bytes
        aesgcm = AESGCM(key)
        nonce = os.urandom(12) #bytes
        ct = aesgcm.encrypt(nonce, data, aad)
        str_key = self.encode_to_string(key)
        str_nonce = self.encode_to_string(nonce)
        key_storage.add_item([str_key, str_nonce])
        return ct

    def decrypt(self, nonce, data, aad, key):
        key = self.decode_to_bytes(key)
        nonce = self.decode_to_bytes(nonce)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, data, aad)

    def scrypt_encrypt(self, password, salt):
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
        data=password.encode('ascii')
        scrypt_key = kdf.derive(data)
        return scrypt_key

    def scrypt_verify(self, password, salt, key):
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
        kdf.verify(password, key)

    def encrypt_with_master_key(self, data, master_key, master_nonce):
        aesgcm = AESGCM(master_key.encode('ascii'))
        ct = aesgcm.encrypt(master_nonce.encode('ascii'), data, b"master-key")
        return ct

    def decrypt_with_master_key(self, data, master_key, master_nonce):
        aesgcm = AESGCM(master_key.encode('ascii'))
        return aesgcm.decrypt(master_nonce.encode('ascii'), data, b"master-key")

    def int_to_bytes(self, x: int) -> bytes:
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')

    def int_from_bytes(self, xbytes: bytes) -> int:
        return int.from_bytes(xbytes, 'big')

    def get_before_slice(self,text):
        encontrado = False
        result = ""
        for letra in text:
            if (letra == "/"):
                encontrado = True
            if (encontrado == False):
                result += letra
        return result

    def get_after_slice(self,text):
        encontrado = False
        result = ""
        for letra in text:
            if (encontrado == True):
                result += letra
            if (letra == "/"):
                encontrado = True
        return result

    def xor(self, bytes1, bytes2):
        return bytes(a ^ b for a, b in zip(bytes1, bytes2))

    def sign_message(self, bytes_message, private_key):
        signature = private_key.sign(
            bytes_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_message(public_key, signature, message):
        value = public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256())
        return value

    @staticmethod
    def get_authority(file):
        # Obtenemos los datos del fichero
        certificate_data = file.read()
        # Deserializamos los datos que estan dentro
        # Generamos un objeto certificado con los datos deserializados del fichero
        authority = x509.load_pem_x509_certificate(certificate_data)
        return authority

    @staticmethod
    def verify_certificate(certificate, upper_level):
        # Obtenemos la clave publica del certificado
        upper_level_public_key = upper_level.public_key()
        # Utilizamos la autoridad superior para verificar el certificado
        # Verificamos el certificado
        value = upper_level_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
        return value

    def sign_out(self):
        self.current_user= None
        self.sign_up = 0