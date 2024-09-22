from __future__ import annotations
from pymongo.cursor import Cursor
from hashlib import sha256
import time
import datetime
import bcrypt
from typing import TYPE_CHECKING
from .Utils import generate_random_string, days_to_seconds
if TYPE_CHECKING:
    from Database import Database

class SessionError(Exception):
    pass

SESSION_TOKEN_LENGTH:int = 32

class Session:
    @staticmethod
    def requires_auth(func):
        def inner(*args, **kwargs):
            target:Session = None
            if kwargs.get("session") is not None:
                target = kwargs.get("session") # type: ignore
            else:
                for arg in args:
                    if(type(arg) is Session):
                        target = arg
            if(not target.valid):
                raise SessionError("Session is not valid")
            a = func(*args,**kwargs)
            return a
        return inner

    @staticmethod
    def requires_permission(perm:str):
        def decorator(func):
            def inner(*args,**kwargs):
                target:Session = None
                if kwargs.get("session") is not None:
                    target = kwargs.get("session") # type: ignore
                else:
                    for arg in args:
                        if(type(arg) is Session):
                            target = arg

                if not target.valid:
                    raise SessionError("Session is not valid")
                if perm not in target.permissions:
                    raise PermissionError("User does not have correct permissions")
                a = func(*args,**kwargs)
                return a
            return inner
        return decorator

    @staticmethod
    def requires_flag(flag:str):
        def decorator(func):
            def inner(*args,**kwargs):
                if not kwargs["session"].valid:
                    raise SessionError("Session is not valid")
                if flag not in kwargs["session"].flags:
                    raise PermissionError("User does not have correct flags")
                func(*args,**kwargs)
            return inner
        return decorator

    def __init__(self,session_id:str, ip:str, database:Database) -> bool:
        self.db:Database = database
        self.id:str = session_id
        self.ip:str = ip
        self.session_data:dict | None = self.__cache_data()
        self.valid:bool = self.__is_valid()
        self.username:str = self.__get_username()
        self.user_cache_data:dict = self.__user_cache()
        self.permissions:list = self.__get_permimssions() # list of permissions (string) [admin, vulnerabilities, inbox, etc]
        self.flags:list = self.__get_flags()

    def __cache_data(self) -> dict | None:
        return self.db.session_collection.find_one(
            {"_id":sha256(self.id.encode("utf-8")).hexdigest()}
        )

    def __is_valid(self):
        if len(self.id) != SESSION_TOKEN_LENGTH:
            return False
        session = self.session_data
        if session is None:
            return False
        if session["ip"] != self.ip:
            return False
        return True

    def __user_cache(self) -> dict:
        data = self.db.collection.find_one({"_id":self.username})
        if data is None:
            self.valid = False
            return {}
        return data

    def __get_username(self) -> str:
        if not self.valid:
            return ""
        return self.db.fernet.decrypt(
            self.session_data["username"].encode("utf-8") # type: ignore  because session_data can't be None if the session is valid.'
        ).decode("utf-8")

    def __get_permimssions(self):
        if not self.valid:
            return []
        return self.user_cache_data["permissions"] # type: ignore

    def __get_flags(self):
        if not self.valid:
            return []
        return list(self.user_cache_data.get("feature-flags",{}).keys()) # type: ignore


    @staticmethod
    def create(username:str, ip:str, user_agent:str, database:Database) -> str:
        """
        NOTE: Username is SHA256 hash of actual username
        """
        session_id = generate_random_string(SESSION_TOKEN_LENGTH)
        session = {
            "_id":sha256(session_id.encode("utf-8")).hexdigest(),
            "expire": datetime.datetime.now() + datetime.timedelta(days=14),
            "ip": ip,
            "user-agent": user_agent,
            "owner-hash": sha256((username+"frii.site").encode("utf-8")).hexdigest(), # "frii.site" acts as a salt, making rainbow table attacts more difficult
            "username": database.fernet.encrypt(bytes(username, "utf-8")).decode(encoding="utf-8")
        }
        database.session_collection.create_index("expire",expireAfterSeconds=1)
        database.session_collection.insert_one(session)
        return session_id
