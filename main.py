from cryptobank import CryptoBank
from user_storage import User_Storage
from account_storage import Account_Storage
from key_storage import Key_Storage
from user_salt_storage import User_Salt_Storage
from account_salt_storage import Account_Salt_Storage

# Inicializamos para evitar errores
Crypto = CryptoBank()
Account_Storage()
User_Storage()
Key_Storage()
User_Salt_Storage()
Account_Salt_Storage()

final = True
#Crypto.master_key = input("Acceso al sistema. \nIntroduce la clave maestra\n")
#Crypto.master_nonce = input("Introduce la contraseña del administrador\n")
while(final):
    print("Elige una opción: ")
    if (Crypto.sign_up == 0):
        print("0: Iniciar Sesión")
        print("1: Crear Sesión")
    if (Crypto.sign_up == 1):
        print("2: Crear Cuenta")
        print("3: Acceder Cuenta")
        print("4: Cerrar sesión")
    if (Crypto.sign_up == 2):
        print("5: Modificar Cuenta")
        print("6: Eliminar Cuenta")
        print("7: Consultar Saldo")
        print("8: Depositar Dinero")
        print("9: Sacar Dinero")
        print("10: Hacer Transferencia")
        print("11: Salir Cuenta")
    print("12: Salir")

    try:
        control = int(input())
    except ValueError:
        # Indicando error
        control = -1
        print("No has introducido un número válido (0-12)")

    if (Crypto.sign_up == 0 and (control != 0 and control != 1 and control != 12)):
        print("Tienes que iniciar sesión")
    elif(Crypto.sign_up == 0 and control == 0):
        # Inicio sesión
        while(True):
            username = input("Introduce tu nombre de usuario. Mínima longitud 8 caracteres: ")
            if len(username) >= 8:
                break
            print("El nombre de usuario debe tener longitud 8 o más")
        while(True):
            password = input("Introduce tu contraseña. Mínima longitud 8 caracteres: ")
            if len(password) >= 8:
                break
            print("La contraseña debe tener longitud 8 o más")
        Crypto.login(username,password)
    elif (Crypto.sign_up == 0 and control == 1):
        # Crear cuenta
        while (True):
            username = input("Introduce tu nombre de usuario. Mínima longitud 8 caracteres: ")
            if len(username) >= 8:
                break
            print("El nombre de usuario debe tener longitud 8 o más")
        while (True):
            password = input("Introduce tu contraseña: ")
            if len(password) >= 8:
                break
            print("La contraseña debe tener longitud 8 o más")
        Crypto.new_user_account(username, password)
    elif (Crypto.sign_up == 1 and control == 2):
        # Crear cuenta bancaria
        while(True):
            acc_name = input("Introduce un nombre para la cuenta. Mínima longitud 8 caracteres: ")
            if len(acc_name) >= 8:
                break
            print("El nombre de la cuenta debe tener longitud 8 o más")
        while(True):
            key = input("Introduce una clave para la cuenta. Mínima longitud 32 caracteres: ")
            if (len(key)>=32):
                break
            print("La clave de la cuenta debe tener longitud 32 o más")
        Crypto.create_account(acc_name, key)
    elif (Crypto.sign_up == 1 and control == 3):
        #Acceder a cuenta bancaria
        while (True):
            acc_name = input("Introduce un nombre para la cuenta. Mínima longitud 8 caracteres: ")
            if len(acc_name) >= 8:
                break
            print("El nombre de la cuenta debe tener longitud 8 o más")
        while (True):
            key = input("Introduce la clave de la cuenta. Mínima longitud 32 caracteres: ")
            if (len(key) >= 32):
                break
            print("La clave de la cuenta debe tener longitud 32 o más")
        Crypto.access_account(acc_name, key)
    elif (Crypto.sign_up == 1 and control == 4):
        Crypto.sign_out()
    elif (Crypto.sign_up == 2 and control == 5):
        # Modificar cuenta bancaria
        while (True):
            acc_name = input("Introduce un nombre para la cuenta. Mínima longitud 8 caracteres: ")
            if len(acc_name) >= 8:
                break
            print("El nombre de la cuenta debe tener longitud 8 o más")
        while (True):
            key = input("Introduce la clave original de la cuenta. Mínima longitud 32 caracteres: ")
            if (len(key) >= 32):
                break
            print("La clave de la cuenta debe tener longitud 32 o más")
        while (True):
            new_key = input("Introduce la nueva clave para la cuenta. Mínima longitud 32 caracteres: ")
            if (len(new_key) >= 32):
                break
            print("La clave de la cuenta debe tener longitud 32 o más")
        Crypto.modify_account(acc_name,key, new_key)
    elif (Crypto.sign_up == 2 and control == 6):
        # Eliminar cuenta bancaria
        Crypto.delete_account()
    elif (Crypto.sign_up == 2 and control == 7):
        # Mirar el saldo de la cuenta
        Crypto.check_balance()
    elif (Crypto.sign_up == 2 and control == 8):
        # Depositar dinero
        quantity = input("Introduce la cantidad a ingresar: ")
        if (not str.isdigit(quantity) or int(quantity) <= 0):
            print("Error: Cantidad invalida, solo números naturales")
        else:
            Crypto.deposit(int(quantity))
    elif (Crypto.sign_up == 2 and control == 9):
        # Sacar dinero
        quantity = input("Introduce la cantidad a sacar: ")
        if (not str.isdigit(quantity) or int(quantity) <= 0):
            print("Error: Cantidad invalida, solo números naturales")
        else:
            Crypto.withdraw(int(quantity))
    elif (Crypto.sign_up == 2 and control == 10):
        # Transferir dinero
        while (True):
            id2 = input("Introduce el nombre de usuario a transferir. Mínima longitud 8 caracteres: ")
            if len(id2) >= 8:
                break
            print("El nombre de usuario debe tener longitud 8 o más")
        while (True):
            acc_name2 = input("Introduce el nombre de la cuenta a transferir. Mínima longitud 8 caracteres: ")
            if len(acc_name2) >= 8:
                break
            print("El nombre de la cuenta debe tener longitud 8 o más")
        quantity = input("Introduce la cantidad a transferir: ")
        if (not str.isdigit(quantity) or int(quantity) <= 0):
            print("Error: Cantidad invalida, solo números naturales")
        else:
            Crypto.transfer(id2, acc_name2, int(quantity))
    elif (Crypto.sign_up == 2 and control == 11):
        # Salir cuenta
        Crypto.log_out()
    elif (control == 12):
        # Salir
        final = False

    elif (control == 100):
        print(Crypto.current_user)
    elif (control == 101):
        print(Crypto.current_account)