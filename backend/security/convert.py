from fastapi import Request
from backend.database.tables.users import Users
from database.tables.sessions import Sessions
from security.session import Session

class Convert:
    def __init__(self):
        pass

    def init_vars(self, users:Users, sessions:Sessions) -> None:
        self.users = users
        self.sessions = sessions
    
    def create(self,request:Request) -> Session:
        session_id:str = request.headers.get("X-Auth-Token")
        return Session(session_id,request.client.host,self.users,self.sessions)