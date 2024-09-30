from .Database import Database
from .Session import Session

class Admin:
    @Session.requires_auth
    @Session.requires_permission("admin")
    def __init__(self,session:Session, db:Database) -> None:
        self.db = db
        self.session = session
    def add_permission(self, perm:str, target=None):
        """
            target: username of reciever
            perm: Permission to give
        """
        if target is None: target = self.session.username
