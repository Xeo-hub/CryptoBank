class Accounts:
    def __init__(self, acc_name, key):
        self.__acc_name = acc_name
        self.__key = key

    def __repr__(self):
        return self.__acc_name + "/" + str(self.__key)

    def __eq__(self, other):
        print(other)
        if (str(self.__acc_name) + "/" + str(self.__key) == str(other)):
            return True

    @property
    def acc_name(self):
        return self.__acc_name

    @acc_name.setter
    def acc_name(self):
        print("Intento de acceso al sistema\nSe procede a cerrar el sistema")
        exit(-2)

    @property
    def key(self):
        return self.__key

    @key.setter
    def key(self,other):
        self.__key = other

