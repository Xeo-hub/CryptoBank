class User:
    def __init__(self, id, password):
        self.user = id
        self.password=password

    def __repr__(self):
        return (self.user,self.password)

"""class User:
    def __init__(self, id, password):
        self.user = id
        self.password = password

    def __repr__(self):
        return str([self.user, self.password])
        self.create_account(password)
        

    def create_account(self, username, password, id):
        if id == self.id:
            self.accounts = {username: password}

    def delente_account(self, username, password):
        #borrar
        if len self.accounts = 0 no borras cuenta
        if no, en la otra cuenta"""
