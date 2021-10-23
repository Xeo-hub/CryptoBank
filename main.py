from cryptobank import CryptoBank
from user_storage import User_Storage
from account_storage import Account_Storage
#En el futuro habrá métodos para quitar la redundancia de los métodos
Crypto = CryptoBank()
Account_Storage()
User_Storage()
final = True
while(final):
    print("Elige una opción: ")
    if (not Crypto.sign_up):
        print("0: Iniciar Sesión")
        print("1: Crear Sesión")
    if (Crypto.sign_up):
        print("2: Crear Cuenta")
        print("3: Modificar Cuenta")
        print("4: Eliminar Cuenta")
        print("5: Depositar dinero")
        print("6: Sacar dinero")
        print("7: Hacer Transferencia")
        print("8: Cerrar Sesión")
    print(": Salir")

    try:
        control = int(input())
    except ValueError:
        # Indicando error
        control = -1
        print("No has introducido un número válido (0-9)")

    if (Crypto.sign_up == False and (control != 0 and control != 1 and control != 9)):
        print("Tienes que iniciar sesión")
    elif(control == 0):
        # Inicio sesión
        username = input("Introduce tu nombre de usuario: ")
        password = input("Introduce tu contraseña: ")
        Crypto.login(username,password)
    elif (control == 1):
        # Crear cuenta
        username = input("Introduce un nombre de usuario: ")
        password = input("Introduce una contraseña: ")
        Crypto.new_user_account(username, password)
    elif (control == 2):
        # Crear cuenta bancaria
        acc_name = input("Introduce un nombre para la cuenta: ")
        key = input("Introduce una clave para la cuenta: ")
        Crypto.create_account(acc_name, key)
    elif (control == 3):
        # Modificar cuenta bancaria
        acc_name = input("Introduce el nombre de la cuenta: ")
        key = input("Introduce la clave de la cuenta: ")
        new_key = input("Introduce la nueva clave para la cuenta: ")
        Crypto.modify_account(acc_name,key,new_key)
    elif (control == 4):
        # Eliminar cuenta bancaria
        acc_name = input("Introduce el nombre de la cuenta: ")
        key = input("Introduce la clave de la cuenta: ")
        Crypto.delete_account(acc_name, key)
    elif (control == 5):
        # Depositar dinero
        acc_name = input("Introduce el nombre de la cuenta: ")
        key = input("Introduce la clave de la cuenta: ")
        quantity = input("Introduce la cantidad a ingresar: ")
        if (not str.isdigit(quantity)):
            print("Error: Cantidad invalidad, solo números enteros")
        else:
            Crypto.deposit(acc_name, key, int(quantity))
    elif (control == 6):
        # Sacar dinero
        acc_name = input("Introduce el nombre de la cuenta: ")
        key = input("Introduce la clave de la cuenta: ")
        quantity = input("Introduce la cantidad a sacar: ")
        if (not str.isdigit(quantity)):
            print("Error: Cantidad invalidad, solo números enteros")
        else:
            Crypto.withdraw(acc_name, key, int(quantity))
    elif (control == 7):
        # Transferir dinero
        acc_name = input("Introduce el nombre de la cuenta: ")
        key = input("Introduce la clave de la cuenta: ")
        id2 = input("Introduce el nombre del usuario a transferir: ")
        acc_name2 = input("Introduce el nombre de la cuenta a transferir: ")
        quantity = input("Introduce la cantidad a transferir: ")
        if (not str.isdigit(quantity)):
            print("Error: Cantidad invalidad, solo números enteros")
        else:
            Crypto.transfer(acc_name, key, id2, acc_name2, int(quantity))
    elif (control == 8):
        # Cerrar sesión
        Crypto.sign_up = False
    elif (control == 9):
        # Salir
        final = False

