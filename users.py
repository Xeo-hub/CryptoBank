class User:
    def __init__(self, id, password):
        self.user = id
        self.password=password

    def __repr__(self):
        return self.user + "/" + self.password

    def __eq__(self,other):
        print(other)
        if (str(self.user) + "/" + str(self.password) == str(other)):
            return True
