from __future__ import annotations
from typing import List, TYPE_CHECKING, Dict, Any, Literal
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


ApiPermission = Literal["register", "modify", "delete", "list"]

ApiType = TypedDict(
    "ApiType",
    {"string": str, "perms": List[ApiPermission], "domains": List[str], "comment": str},
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
        @wraps(func)
        def wrapper(*args, **kwargs):
            target: Api | None = Api.find_api_instance(args, kwargs)
            if target is None or not target.valid:
                raise ApiError("API key is not valid")
            a = func(*args, **kwargs)
            return a

        return wrapper

    @staticmethod
    def requires_permission(permission: ApiPermission):
        def decor(func):
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                target: Api | None = Api.find_api_instance(args, kwargs)

                if target is None or not target.valid:
                    raise ApiError("API is not valid")

                if permission not in target.permissions:
                    raise ApiPermissionError(f"API key missing permission {permission}")

                target_domain: str | None = kwargs.get("domain")

                if permission == "modify" or permission == "delete":
                    if target_domain is None:
                        logger.error(
                            "Target domain not specified in kwargs as 'domain'"
                        )
                        logger.debug(f"Args: {args}; kwargs: {kwargs}")
                        raise ValueError("Domain not specified")

                    logger.info(target_domain)
                    logger.info(target.affected_domains)
                    if (
                        target_domain.replace(".", "[dot]")
                        not in target.affected_domains
                    ):
                        logger.warning(f"{target_domain} not in affected domain")
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

        self.key_data: ApiType | None = self.__cache_data()
        self.valid: bool = self.__is_valid()

        self.user_cache_data: "UserType" = self.__user_cache()
        self.username: str = self.__get_id()
        self.permissions: list = self.__get_permimssions()

        if self.key_data:
            self.affected_domains: List[str] = self.key_data.get("domains", [])

            if "*" in self.affected_domains:
                logger.info(
                    "Wildcard in affected domains! Filling with users domains..."
                )
                self.affected_domains = list(self.user_cache_data["domains"].keys())

            self.user_domains: Dict[str, DomainFormat | None] = {
                domain: self.user_cache_data["domains"].get(domain)
                for domain in self.affected_domains
            }

        else:
            self.affected_domains = []
            self.user_domains = {}

    def __cache_data(self) -> ApiType | None:
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
        if not self.valid or self.key_data is None:
            return []

        return self.key_data["perms"]

    @staticmethod
    def create(
        username: str,
        users: Users,
        comment: str,
        permissions: List[ApiPermission],
        domains: List[str],
    ) -> str:

        api_key: str = "$APIV2=" + Encryption.generate_random_string(32)
        user_data: UserType | None = users.find_user({"_id": username})
        if user_data is None:
            raise ValueError("User not found")

        user_domains: Dict[str, "DomainFormat"] = user_data["domains"]

        for domain in domains:
            if domain not in list(user_domains.keys()) and domain != "*":
                logger.warning(f"Domain {domain} not in user_domain")
                raise PermissionError(f"User does not own domain {domain}")

        key: ApiType = {
            "string": users.encryption.encrypt(api_key),
            "perms": permissions,
            "domains": domains,
            "comment": comment,
        }

        encrypted_api_key: str = Encryption.sha256(api_key + "frii.site")
        users.modify_document(
            {"_id": username}, "$set", f"api-keys.{encrypted_api_key}", key
        )
        return api_key

    def delete(self, key_id: str) -> bool:
        """Deletes a specific API key.

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
