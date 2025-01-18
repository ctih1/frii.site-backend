from __future__ import annotations
from typing import TypedDict, List, TYPE_CHECKING
import os
from enum import Enum
import threading
import time
import datetime
import base64
from cryptography import fernet
import pyotp
from fastapi import Request
from database.table import Table
from security.encryption import Encryption
from debug.logger import Logger
from functools import wraps # test

if TYPE_CHECKING:
    from database.tables.general import General
    from database.tables.general import UserType
    from database.tables.sessions import Sessions

l:Logger = Logger("session.py")


class SessionError(Exception):
    pass

class SessionPermissonError(Exception):
    pass

class SessionFlagError(Exception):
    success:bool

SessionCreateStatus = TypedDict(
    "SessionCreateStatus", { "success":bool, "mfa_required":bool, "code":str | None }
)

SESSION_TOKEN_LENGTH: int = 32


SessionType = TypedDict(
    "SessionType", {"user-agent": str, "ip": str, "expire": int, "hash": str}
)


class UserManager(threading.Thread):
    # a thread to track user data (for security)
    def __init__(self, general:General, ip, username):
        super(UserManager, self).__init__()
        self.table: General = general
        self.daemon = True
        self.ip = ip
        self.username = username

    def start(self):
        self.table.table.update_one(
            {"_id": self.username},
            {"$push": {"accessed-from": self.ip}, "$set": {"last-login": time.time()}},
        )


class Session:
    @staticmethod
    def find_session_instance(args:tuple, kwargs:dict) -> Session | None:
        """Finds session from args or kwargs.
        """
        target: Session | None = None
        if kwargs.get("session") is not None:
            target = kwargs.get("session")  # type: ignore
        else:
            for arg in args:
                if type(arg) is Session:
                    target = arg
        return target

    @staticmethod
    def requires_auth(func):
        """A decorator that checks if the session passed is valid.
        How to use:

        To use:
            A: pass a key word arguement "session"
            B: pass an arguement with the sesson type

            Example:
                ```
                a = Session() # a session object
                get_user_domains("domain", a, "1.2.3.4")
                ```

                or

                `get_user_domains(domain="domain", session=a, content="1.2.3.4") # note the "session" must be the keyword if you use keyword args`
        To create:
            ```
            @Session.requires_auth
            def get_user_data(domain:str, session:Session, content:str) ->  None:
                ...
            ```

        Throws:
            SessionError if session is not valid
        """

        @wraps(func)
        def wrapper(*args, **kwargs):
            target: Session = Session.find_session_instance(args,kwargs)
            if not target.valid:
                raise SessionError("Session is not valid")
            a = func(*args, **kwargs)
            return a

        return wrapper

    @staticmethod
    def requires_permission(permission: str):
        """A decorator that checks if the session passed is valid and has the correct permission
        Use the same way as @requires_auth, but pass args into this.

        To create:
            List of permissions:
                - admin: Not used anywhere atp
                - reports: Used to manage and view vulnerabilities
                - wildcards: To use wildcards in domains (*.frii.site)
                - userdetails: To view user details for abuse complaints
            ```
            @requires_permission(perm="admin")
            def ban_user(target_user:str, reason:str, session:Session) -> None:
                ...
            ```
        To use:
            Same way as @requires_auth

        Throws:
            SessionError if session is invalid
            SessionPermissionError: if permission is not met
        """

        def decor(func):
            @wraps(func)
            def wrapper(*args,**kwargs):
                target: Session = Session.find_session_instance(args,kwargs)
                if not target.valid:
                    raise SessionError("Session is not valid")
                if permission not in target.permissions:
                    raise SessionPermissonError(
                        "User does not have correct permissions"
                    )
                a = func(*args, **kwargs)
                return a
            return wrapper
        return decor

    @staticmethod
    def requires_flag(flag: str):
        """To check if user has a specific feature flag
        To use:
            Same as @requires_auth
        To create:
            ```
            @requires_flag(flag="store")
            def get_store_credits(session:Session) -> None:
                ...
            ```
        Throws:
            SessionError if session is not valid
            SessionFlagError if user does not have the flag.
        """
        def decor(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                target: Session = Session.find_session_instance(args,kwargs)
                if not target.valid:
                    raise SessionError("Session is not valid")
                if flag not in target.flags:
                    raise SessionFlagError("User does not have correct flags")
                func(*args, **kwargs)
            return wrapper
        return decor

    def __init__(self, session_id:str, ip:str, general: General, sessions: Sessions) -> None:
        """Creates a Session object.
        Arguements:
            session_id: The id of the session string of length SESSION_TOKEN_LENGHT. Usually found in X-Auth-Token header.
            ip: The request's ip
            database: Instance of the database class
        """
        self.session_table:Sessions = sessions
        self.general_table:General = general
        self.encryption: Encryption = Encryption(os.getenv("ENC_KEY"))

        self.id = session_id
        self.ip = ip

        self.session_data: dict | None = self.__cache_data()
        self.valid: bool = self.__is_valid()
        self.username: str = self.__get_username()

        self.user_cache_data: UserType = self.__user_cache()
        self.permissions: list = self.__get_permimssions()
        self.flags: list = self.__get_flags()


    def __cache_data(self) -> dict | None:
        return self.session_table.find_item({"_id":Encryption.sha256(self.id)})

    def __is_valid(self):
        if len(self.id) != SESSION_TOKEN_LENGTH:
            l.info("Session is not valid: length")
            return False
        
        if self.session_data is None:
            l.info("Session is not valid: None")
            return False
        
        if self.session_data["ip"] != self.ip:
            l.info("Session is not valid: ip")
            return False
        
        return True

    def __user_cache(self) -> dict:
        data:dict = self.general_table.find_item({"_id":self.username})

        if data is None:
            self.valid = False
            return {}
        
        return data

    def __get_username(self) -> str:
        if not self.valid or self.session_data is None:
            return ""


        return self.encryption.decrypt(self.session_data["username"])
    
    def __get_permimssions(self):
        if not self.valid:
            return []
        
        return [permission for permission in self.user_cache_data["permissions"] if self.user_cache_data["permissions"].get(permission,True) is not False]
    
    def __get_flags(self):
        if not self.valid:
            return []
    
        return list(self.user_cache_data.get("feature-flags", {}).keys())  # type: ignore

    def get_active(self) -> List[SessionType]:
        if not self.valid:
            return []
        
        session_list: List[SessionType] = []
        owner_hash = Encryption.sha256(self.username + "frii.site")

        for session in self.session_table.find_items({"owner-hash": owner_hash}):
            session_list.append(
                {
                    "user-agent": session["user-agent"],
                    "ip": session["ip"],
                    "expire": session["expire"].timestamp(),
                    "hash": session["_id"],
                }
            )
        return session_list

    @staticmethod
    def create(username: str, ip: str, user_agent: str, general: General, session_table:Sessions) -> SessionCreateStatus:
        """
        Creates a new session for the given user.
        Args:
            username (str): The username of the user.
            ip (str): The IP address of the user.
            user_agent (str): The user agent string of the user's browser.
            general (General): An instance of the General class for database operations.
            session_table (Sessions): An instance of the Sessions class for session management.
        Returns:
            SessionCreateStatus: An object indicating the success of the session creation, 
                                    whether multi-factor authentication (MFA) is required, 
                                    and the session ID if successful.
        """




        if general.find_item({"_id":username}).get("totp-key") is not None:
            return SessionCreateStatus(
                success = False, mfa_required = True, code = None
            )

        session_id = Encryption.generate_random_string(SESSION_TOKEN_LENGTH)

        session = {
            "_id": Encryption.sha256(session_id),
            "expire": datetime.datetime.now() + datetime.timedelta(days=7),
            "ip": ip,
            "user-agent": user_agent,
            "owner-hash": Encryption.sha256(username + "frii.site"),  # "frii.site" acts as a salt, making rainbow table attacts more difficult
            "username": Encryption(os.getenv("ENC_KEY")).encrypt(username)
        }

        session_table.delete_in_time(date_key="expire")
        session_table.create_index("owner-hash")
        session_table.insert_document(session)

        general.modify_document(
            filter={"$and":[
                    {"_id":username}, {"permissions.invite":{"$exists":False}}
                    ]
                },
            key="permission.invite",
            value=True,
            operation="$set",
            ignore_no_matches=True
        )
        
        UserManager(general, ip, username).start() # updates `last-login` and `accessed-from` fields of user
        return SessionCreateStatus(
            success=True, mfa_required=False, code=session_id
        )

    def create_2fa(self):
        if not self.valid:
            raise SessionError()
        
        key_for_user = base64.b32encode(Encryption.generate_random_string(16).encode("utf-8")).decode("utf-8")

        data = self.general_table.find_item({"_id":self.username})

        if data.get("totp-key") is not None:
            return None
        
        self.general_table.modify_document(
            {"_id":self.username},
            key="totp-key",
            value=self.encryption.encrypt(key_for_user),
            operation="$set"
        )

        return pyotp.totp.TOTP(key_for_user).provisioning_uri(
            self.username, "frii.site"
        )


    @staticmethod
    def verify_2fa(code: str, user_id: str, general: Table):
        """Verify's 2FA TOTP code (as used in google authenticator)
        Returns boolean if code is correct
        """
        key = general.find_item({"_id": user_id}).get("totp-key")
        decrypted_key = Encryption(os.getenv("ENC_KEY")).decrypt(key)

        return pyotp.totp.TOTP(decrypted_key).verify(code)

    @staticmethod
    def clear_sessions(user_id:str, session_table:Sessions):
        """Deletes every sesion that user has. Used mainly for resetting the password
        """

        session_table.delete_many({
            "owner-hash": Encryption.sha256(user_id+"frii.site")
        })

        return True

    def delete(self, id):
        """Deletes a specific session.

        Arguements:
            self: being an instance of Session to authenticate that the person trying to delete the session actually has permissions to do so
            id: sha256 hash of the session_id, that will be deleted
        """
        if not self.valid:
            return False
        
        data = self.general_table.find_item({"_id": id})

        session_username = self.encryption.decrypt(data["username"])

        if self.username != session_username:
            return False
        
        self.session_table.delete_document({"_id":id})
        return True
