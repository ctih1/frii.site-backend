from fastapi import Request
from database.tables.general import General
from database.tables.sessions import Sessions
from security.session import Session

class Convert:
    def __init__(self):
        pass

    def init_vars(self, general:General, sessions:Sessions) -> None:
        self.general = general
        self.sessions = sessions
    
    def create(self,request:Request) -> Session:
        session_id:str = request.headers.get("X-Auth-Token")
        return Session(session_id,request.client.host,self.general,self.sessions)