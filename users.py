import os

class User:
    def __init__(self, id, password):
        self.__user = id
        self.__password = password

    def __repr__(self):
        return self.__user + "/" + self.__password

    def __eq__(self, other):
        if str(self.__user) + "/" + str(self.__password) == str(other):
            return True

    @property
    def user(self):
        return self.__user

    @user.setter
    def user(self, otro):
        self.__user = otro