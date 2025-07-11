from __future__ import annotations
from typing import List, TYPE_CHECKING, Dict, Any
from typing_extensions import TypedDict
import logging
import os
import time
import datetime
import threading
import base64
import pyotp
from fastapi import Request
from cryptography import fernet
from functools import wraps

from database.table import Table
from security.encryption import Encryption
from database.exceptions import UserNotExistError

if TYPE_CHECKING:
    from database.tables.users import Users
    from database.tables.users import UserType
    from database.tables.sessions import Sessions
    from database.tables.domains import DomainFormat


class ApiError(Exception): ...


class ApiPermissionError(Exception): ...


class ApiRangeError(Exception): ...


SessionType = TypedDict(
    "SessionType", {"user-agent": str, "ip": str, "expire": int, "hash": str}
)


logger = logging.getLogger("frii.site")


class UserManager(threading.Thread):
    # a thread to track user data (for security)
    def __init__(self, users: Users, ip, userid):
        super(UserManager, self).__init__()
        self.table: Users = users
        self.daemon = True
        self.ip = ip
        self.userid = userid

    def start(self):
        self.table.table.update_one(
            {"_id": self.userid},
            {"$push": {"accessed-from": self.ip}, "$set": {"last-login": time.time()}},
        )


class Api:
    @staticmethod
    def find_api_instance(args: tuple, kwargs: dict) -> Api | None:
        """Finds session from args or kwargs."""
        target: Api | None = None
        if kwargs.get("api") is not None:
            target = kwargs.get("api")  # type: ignore
        else:
            for arg in args:
                if type(arg) is Api:
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
            target: Api = Api.find_api_instance(args, kwargs)
            if not target.valid:
                raise ApiError("API key is not valid")
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
            def wrapper(*args, **kwargs) -> Any:
                target: Api | None = Api.find_api_instance(args, kwargs)

                if target is None or not target.valid:
                    raise ApiError("API is not valid")

                if permission not in target.permissions:
                    raise ApiPermissionError("User does not have correct permissions")

                target_domain: str | None = kwargs.get("domain")

                if permission == "content":
                    if target_domain is None:
                        logger.error(
                            "Target domain not specified in kwargs as 'domain'"
                        )
                        logger.debug(f"Args: {args}; kwargs: {kwargs}")
                        raise ValueError("Domain not specified")

                    logger.info(target_domain)
                    logger.info(target.affected_domains)
                    if target_domain not in target.affected_domains:
                        raise ApiRangeError("User cannot access this domain")

                    logger.debug(f"API Key can modify domain {target_domain}")

                of = func(*args, **kwargs)
                return of

            return wrapper

        return decor

    def __init__(self, api_key: str, users: Users) -> None:
        """Creates a Session object.
        Arguements:
            session_id: The id of the session string of length SESSION_TOKEN_LENGHT. Usually found in X-Auth-Token header.
            ip: The request's ip
            database: Instance of the database class
        """
        self.users_table: Users = users
        self.encryption: Encryption = users.encryption

        self.key: str = api_key
        self.encrypted_key: str = Encryption.sha256(api_key + "frii.site")

        self.key_data: dict | None = self.__cache_data()
        self.valid: bool = self.__is_valid()

        self.user_cache_data: "UserType" = self.__user_cache()
        self.username: str = self.__get_id()
        self.permissions: list = self.__get_permimssions()

        if self.key_data:
            self.affected_domains: dict = self.key_data.get("domains", {})
        else:
            self.affected_domains = {}

    def __cache_data(self) -> dict | None:
        user_data = self.users_table.find_item(
            {f"api-keys.{self.encrypted_key}": {"$exists": True}}
        )
        if user_data is None:
            raise ValueError("User not found")
        return user_data["api-keys"][self.encrypted_key]

    def __is_valid(self):
        if self.key_data is None:
            return False

        return True

    def __user_cache(self) -> "UserType":
        data: "UserType" | None = self.users_table.find_item({f"api-keys.{self.encrypted_key}": {"$exists": True}})  # type: ignore[assignment]

        if data is None:
            self.valid = False
            return {}  # type: ignore[typeddict-item]

        return data

    def __get_id(self) -> str:
        if not self.valid or self.key_data is None:
            return ""

        return self.user_cache_data["_id"]

    def __get_permimssions(self):
        if not self.valid:
            return []

        return self.key_data["perms"]

    @staticmethod
    def create(
        username: str, users: Users, comment: str, permissions: List[str]
    ) -> str:
        """
        Creates a new session for the given user.
        Args:
            username (str): The username of the user.
            ip (str): The IP address of the user.
            user_agent (str): The user agent string of the user's browser.
            users (Users): An instance of the Users class for database operations.
            session_table (Sessions): An instance of the Sessions class for session management.
        Returns:
            SessionCreateStatus: An object indicating the success of the session creation,
                                    whether multi-factor authentication (MFA) is required,
                                    and the session ID if successful.
        """

        api_key: str = "$APIV1=" + Encryption.generate_random_string(32)
        user_data: UserType | None = users.find_user({"_id": username})
        if user_data is None:
            raise ValueError("User not found")

        user_domains: Dict[str, "DomainFormat"] = user_data["domains"]

        for domain in user_domains:
            if domain not in list(user_domains.keys()):
                raise PermissionError("User does not own domain")

        key = {
            "string": users.encryption.encrypt(api_key),
            "perms": permissions,
            "domains": user_domains,
            "comment": comment,
        }

        encrypted_api_key: str = Encryption.sha256(api_key + "frii.site")
        users.modify_document(
            {"_id": username}, "$set", f"api-keys.{encrypted_api_key}", key
        )
        return api_key

    def delete(self, key_id: str) -> bool:
        """Deletes a specific session.

        Arguements:
            self: being an instance of Session to authenticate that the person trying to delete the session actually has permissions to do so
            id: sha256 hash of the session_id, that will be deleted

        Throws:
            SessionError: target session does not exist
            SessionPermissionError: session does not belong to user
        """
        raise NotImplementedError("Implement")

        if not self.valid:
            return False

        data: dict | None = self.session_table.find_item({"_id": key_id})

        if data is None:
            raise SessionError("Session does not exist")  # type: ignore

        session_username: str = self.encryption.decrypt(data["username"])

        if self.username != session_username:
            raise SessionPermissonError("Invalid username for session")  # type: ignore

        self.session_table.delete_document({"_id": key_id})
        return True
