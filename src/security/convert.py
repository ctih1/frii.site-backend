from fastapi import Request
from database.tables.users import Users
from database.tables.sessions import Sessions
from security.session import Session, SessionError
from security.api import Api, ApiError, ApiPermissionError


class Convert:
    def __init__(self): ...

    def init_vars(self, users: Users, sessions: Sessions) -> None:
        self.users = users
        self.sessions = sessions

    def create(self, request: Request) -> Session:
        session_id: str | None = request.headers.get("X-Auth-Token")
        if session_id is None:
            raise SessionError("Session id is none")

        return Session(session_id, request.client.host, self.users, self.sessions)  # type: ignore[union-attr]


class ConvertAPI:
    def __init__(self): ...
    def init_vars(self, users: Users) -> None:
        self.users = users

    def create(self, request: Request) -> Api:
        api_key: str | None = request.headers.get("X-API-Token")
        if api_key is None:
            raise ApiError("API Key not specified (X-API-Token header missing)")

        return Api(api_key, self.users)
