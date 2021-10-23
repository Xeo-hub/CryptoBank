class Accounts:
    def __init__(self, acc_name, key):
        self.acc_name = acc_name
        self.key = key

    def __repr__(self):
        return self.acc_name + "/" + self.key

    def __eq__(self, other):
        print(other)
        if (str(self.acc_name) + "/" + str(self.key) == str(other)):
            return True