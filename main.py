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
        print("No has introducido un número válido (0-11)")

    if (Crypto.sign_up == 0 and (control != 0 and control != 1 and control != 11)):
        print("Tienes que iniciar sesión")
    elif(Crypto.sign_up == 0 and control == 0):
        # Inicio sesión
        username = input("Introduce tu nombre de usuario: ")
        password = input("Introduce tu contraseña: ")
        Crypto.login(username,password)
    elif (Crypto.sign_up == 0 and control == 1):
        # Crear cuenta
        username = input("Introduce un nombre de usuario: ")
        password = input("Introduce una contraseña: ")
        Crypto.new_user_account(username, password)
    elif (Crypto.sign_up == 1 and control == 2):
        # Crear cuenta bancaria
        acc_name = input("Introduce un nombre para la cuenta: ")
        key = input("Introduce una clave para la cuenta: ")
        Crypto.create_account(acc_name, key)
    elif (Crypto.sign_up == 1 and control == 3):
        #Acceder a cuenta bancaria
        acc_name = input("Introduce el nombre de la cuenta: ")
        key = input("Introduce la clave de la cuenta: ")
        Crypto.access_account(acc_name, key)
    elif (Crypto.sign_up == 1 and control == 4):
        Crypto.sign_out()
    elif (Crypto.sign_up == 2 and control == 5):
        # Modificar cuenta bancaria
        acc_name = input("Introduce el nombre de la cuenta: ")
        new_key = input("Introduce la nueva clave para la cuenta: ")
        Crypto.modify_account(acc_name, new_key)
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
        id2 = input("Introduce el nombre del usuario a transferir: ")
        acc_name2 = input("Introduce el nombre de la cuenta a transferir: ")
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

