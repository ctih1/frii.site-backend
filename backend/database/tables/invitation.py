from database.tables.general import General

class Invites(General):
    def __init__(self):
        super().__init__()

    def is_valid(self, code:str) -> bool:
        raise NotImplementedError()