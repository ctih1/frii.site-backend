from __future__ import annotations
from pymongo.cursor import Cursor
from hashlib import sha256, sha1
import time
import datetime
import pyotp
import bcrypt
import base64
import threading
from typing import TypedDict
from typing import List
from typing import TYPE_CHECKING
from enum import Enum
from .Logger import Logger
from .Utils import generate_random_string, days_to_seconds, generate_password

l = Logger("Session.py", "None", "None")

if TYPE_CHECKING:
    from Database import Database


class SessionError(Exception):
    pass


class SessionPermissonError(Exception):
    pass


class SessionFlagError(Exception):
    success:bool

SessionCreateStatus = TypedDict(
    "SessionCreateStatus", { "success":bool, "mfa_required":bool, "code":str }
)

SESSION_TOKEN_LENGTH: int = 32

SessionType = TypedDict(
    "SessionType", {"user-agent": str, "ip": str, "expire": int, "hash": str}
)


class UserManager(threading.Thread):
    # a thread to track user data (for security)
    def __init__(self, db: Database, ip, username):
        super(UserManager, self).__init__()
        self.db: Database = db
        self.daemon = True
        self.ip = ip
        self.username = username

    def start(self):
        self.db.collection.update_one(
            {"_id": self.username},
            {"$push": {"accessed-from": self.ip}, "$set": {"last-login": time.time()}},
        )


class Session:
    @staticmethod
    def find_session_instance(args:tuple, kwargs:dict) -> Session:
        """Finds session from args or kwargs.
        """
        target: Session = None
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
        def inner(*args, **kwargs):
            target: Session = Session.find_session_instance(args,kwargs)
            if not target.valid:
                raise SessionError("Session is not valid")
            a = func(*args, **kwargs)
            return a

        return inner

    @staticmethod
    def requires_permission(perm: str):
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
        def decorator(func):
            def inner(*args, **kwargs):
                target: Session = Session.find_session_instance(args,kwargs)
                if not target.valid:
                    raise SessionError("Session is not valid")
                if perm not in target.permissions:
                    raise SessionPermissonError(
                        "User does not have correct permissions"
                    )
                a = func(*args, **kwargs)
                return a

            return inner

        return decorator

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
        def decorator(func):
            def inner(*args, **kwargs):
                target: Session = Session.find_session_instance(args,kwargs)
                if not target.valid:
                    raise SessionError("Session is not valid")
                if flag not in target.flags:
                    raise SessionFlagError("User does not have correct flags")
                func(*args, **kwargs)
            return inner
        return decorator

    def __init__(self, session_id: str, ip: str, database: Database) -> None:
        """Creates a Session object.
        Arguements:
            session_id: The id of the session string of length SESSION_TOKEN_LENGHT. Usually found in X-Auth-Token header.
            ip: The request's ip
            database: Instance of the database class
        """
        self.db: Database = database
        self.id: str = session_id
        self.ip: str = ip
        self.session_data: dict | None = self.__cache_data()
        self.valid: bool = self.__is_valid()
        self.username: str = self.__get_username()
        self.user_cache_data: dict = self.__user_cache()
        self.permissions: list = (
            self.__get_permimssions()
        )  # list of permissions (string) [admin, vulnerabilities, inbox, etc]
        self.flags: list = self.__get_flags()

    def __cache_data(self) -> dict | None:
        return self.db.session_collection.find_one(
            {"_id": sha256(self.id.encode("utf-8")).hexdigest()}
        )

    def __is_valid(self):
        if len(self.id) != SESSION_TOKEN_LENGTH:
            l.info("Session is not valid: length")
            return False
        session = self.session_data
        if session is None:
            l.info("Session is not valid: None")
            return False
        if session["ip"] != self.ip:
            l.info("Session is not valid: ip")
            return False
        return True

    def __user_cache(self) -> dict:
        data = self.db.collection.find_one({"_id": self.username})
        if data is None:
            self.valid = False
            return {}
        return data

    def __get_username(self) -> str:
        if not self.valid:
            return ""
        return self.db.fernet.decrypt(
            self.session_data["username"].encode("utf-8")  # type: ignore  because session_data can't be None if the session is valid.'
        ).decode("utf-8")

    def __get_permimssions(self):
        if not self.valid:
            return []
        return self.user_cache_data["permissions"]  # type: ignore

    def __get_flags(self):
        if not self.valid:
            return []
        return list(self.user_cache_data.get("feature-flags", {}).keys())  # type: ignore

    def get_active(self) -> List[SessionType]:
        if not self.valid:
            return []
        session_list: List[SessionType] = []
        owner_hash = sha256((self.username + "frii.site").encode("utf-8")).hexdigest()
        cursor = self.db.session_collection.find({"owner-hash": owner_hash})
        for session in cursor:
            session_list.append(
                {
                    "user_agent": session["user-agent"],
                    "ip": session["ip"],
                    "expire": session["expire"].timestamp(),
                    "hash": session["_id"],
                }
            )
        return session_list

    @staticmethod
    def create(username: str, ip: str, user_agent: str, database: Database) -> SessionCreateStatus:
        """Does NOT check password validity. Creates a new session for user.

        Arguements:
            username: SHA256 hash of username
            ip: the ip used to make the request
            user_agent: the user agent of the request
            database: instance of database class
        """
        if database.collection.find_one({"_id":username}).get("totp-key") is not None: # type: ignore ; user has set up 2FA
            return SessionCreateStatus(
                success=False,mfa_required=True,code=None
            )

        session_id = generate_random_string(SESSION_TOKEN_LENGTH)
        session = {
            "_id": sha256(session_id.encode("utf-8")).hexdigest(),
            "expire": datetime.datetime.now() + datetime.timedelta(days=7),
            "ip": ip,
            "user-agent": user_agent,
            "owner-hash": sha256(
                (username + "frii.site").encode("utf-8")
            ).hexdigest(),  # "frii.site" acts as a salt, making rainbow table attacts more difficult
            "username": database.fernet.encrypt(bytes(username, "utf-8")).decode(
                encoding="utf-8"
            ),
        }
        database.session_collection.create_index("expire", expireAfterSeconds=1) # deletes document from database as soon as it expiress
        database.session_collection.create_index(
            "owner-hash"
        )  # optimize lookup times on get_active
        database.session_collection.insert_one(session) # places session into the database
        UserManager(database, ip, username).start() # updates `last-login` and `accessed-from` fields of user
        return SessionCreateStatus(
            success=True, mfa_required=False, code=session_id
        )

    def create_2fa(self):
        if not self.valid:
            raise SessionError()
        key_for_user = base64.b32encode(generate_password(16).encode("utf-8")).decode(
            "utf-8"
        )
        data = self.db.collection.find_one({"_id":self.username})
        if data.get("totp-key") is not None:
            return None
        self.db.collection.update_one(
            {"_id": self.username},
            {
                "$set": {
                    "totp-key": self.db.fernet.encrypt(
                        key_for_user.encode("utf-8")
                    ).decode("utf-8")
                }
            },
            upsert=False,
        )
        return pyotp.totp.TOTP(key_for_user).provisioning_uri(
            self.username, "frii.site"
        )

    @staticmethod
    def verify_2fa(code: str, userid: str, database: Database):
        """Verify's 2FA TOTP code (as used in google authenticator)
        Returns boolean if code is correct
        """
        key = database.collection.find_one({"_id": userid}).get("totp-key")
        decrypted_key = database.fernet.decrypt(key.encode("utf-8")).decode("utf-8")

        return pyotp.totp.TOTP(decrypted_key).verify(code)

    def clear_sessions(self):
        """Deletes every sesion that user has. Used mainly for resetting the password
        """
        if not self.valid:
            return False
        self.db.session_collection.delete_many(
            {
                "owner-hash": sha256(
                    (self.username + "frii.site").encode("utf-8")
                ).hexdigest()
            }
        )
        return True

    def delete(self, id):
        """Deletes a specific session.

        Arguements:
            self: being an instance of Session to authenticate that the person trying to delete the session actually has permissions to do so
            id: sha256 hash of the session_id, that will be deleted
        """
        if not self.valid:
            return False
        data = self.db.session_collection.find_one({"_id": id})

        session_username = self.db.fernet.decrypt(
            data["username"].encode("utf-8")
        ).decode("utf-8")

        if self.username != session_username:
            return False
        self.db.session_collection.delete_one({"_id": id})
        return True
