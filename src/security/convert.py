from fastapi import Request
from database.tables.users import Users
from database.tables.sessions import Sessions
from security.session import Session
from security.session import SessionError

class Convert:
    def __init__(self):
        pass

    def init_vars(self, users:Users, sessions:Sessions) -> None:
        self.users = users
        self.sessions = sessions
    
    def create(self,request:Request) -> Session:
        session_id:str | None = request.headers.get("X-Auth-Token")
        if session_id is None:
            raise SessionError("Session id is none")
        
        return Session(session_id,request.client.host,self.users,self.sessions) # type: ignore[union-attr]