from __future__ import annotations
from typing import List, TYPE_CHECKING
from typing_extensions import TypedDict
import os
import time
import datetime
import threading
import base64
import pyotp
from fastapi import Request
from cryptography import fernet
from functools import wraps
import logging

from database.table import Table
from security.encryption import Encryption
from database.exceptions import UserNotExistError

if TYPE_CHECKING:
    from database.tables.users import Users
    from database.tables.users import UserType
    from database.tables.sessions import Sessions


class SessionError(Exception):
    pass


class SessionPermissonError(Exception):
    pass


class SessionFlagError(Exception):
    success: bool


class VerificationError(Exception):
    pass


SessionCreateStatus = TypedDict(
    "SessionCreateStatus", {"success": bool, "mfa_required": bool, "code": str | None}
)

SESSION_TOKEN_LENGTH: int = 32


SessionType = TypedDict(
    "SessionType", {"user-agent": str, "ip": str, "expire": int, "hash": str}
)

logger = logging.getLogger("frii.site")


class UserManager(threading.Thread):
    # a thread to track user data (for security)
    def __init__(self, users: Users, ip, username):
        super(UserManager, self).__init__()
        self.table: Users = users
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
    def find_session_instance(args: tuple, kwargs: dict) -> Session | None:
        """Finds session from args or kwargs."""
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
            target: Session = Session.find_session_instance(args, kwargs)
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
            def wrapper(*args, **kwargs):
                target: Session = Session.find_session_instance(args, kwargs)
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
                target: Session = Session.find_session_instance(args, kwargs)
                if not target.valid:
                    raise SessionError("Session is not valid")
                if flag not in target.flags:
                    raise SessionFlagError(f"User is missing flag {flag}")
                a = func(*args, **kwargs)
                return a

            return wrapper

        return decor

    def __init__(
        self, session_id: str, ip: str, users: Users, sessions: Sessions
    ) -> None:
        """Creates a Session object.
        Arguements:
            session_id: The id of the session string of length SESSION_TOKEN_LENGHT. Usually found in X-Auth-Token header.
            ip: The request's ip
            database: Instance of the database class
        """
        self.session_table: Sessions = sessions
        self.users_table: Users = users
        self.encryption: Encryption = Encryption(os.getenv("ENC_KEY"))  # type: ignore[arg-type]

        self.id = session_id
        self.ip = ip

        self.session_data: dict | None = self.__cache_data()
        self.valid: bool = self.__is_valid()
        self.username: str = self.__get_username()
        self.user_id = self.username

        self.user_cache_data: "UserType" = self.__user_cache()
        self.permissions: list = self.__get_permimssions()
        self.flags: list = self.__get_flags()

    def __cache_data(self) -> dict | None:
        return self.session_table.find_item({"_id": Encryption.sha256(self.id)})

    def __is_valid(self):
        if len(self.id) != SESSION_TOKEN_LENGTH:
            return False

        if self.session_data is None:
            return False

        if self.session_data["ip"] != self.ip:
            return False

        return True

    def __user_cache(self) -> "UserType":
        data: "UserType" | None = self.users_table.find_user({"_id": self.username})

        if data is None:
            self.valid = False
            return {}  # type: ignore[typeddict-item]

        return data

    def __get_username(self) -> str:
        if not self.valid or self.session_data is None:
            return ""

        return self.encryption.decrypt(self.session_data["_id"])

    def __get_permimssions(self):
        if not self.valid:
            return []

        return [
            permission
            for permission in self.user_cache_data["permissions"]
            if self.user_cache_data["permissions"].get(permission, True) is not False
        ]

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
    def create(
        username: str,
        real_username: str | None,
        mfa_code: str | None,
        ip: str,
        user_agent: str,
        users: Users,
        session_table: Sessions,
    ) -> SessionCreateStatus:
        """
        Creates a new session for the given user.
        Args:
            username (str): The username of the user.
            mfa_code (str): a possible mfa code for the users account
            ip (str): The IP address of the user.
            user_agent (str): The user agent string of the user's browser.
            users (Users): An instance of the Users class for database operations.
            session_table (Sessions): An instance of the Sessions class for session management.
        Returns:
            SessionCreateStatus: An object indicating the success of the session creation,
                                    whether multi-factor authentication (MFA) is required,
                                    and the session ID if successful.
        """

        user_data: "UserType" | None = users.find_user({"_id": username})

        if user_data is None:
            raise UserNotExistError()

        user_has_mfa = user_data.get("totp", {}).get("verified")
        user_mfa_key = user_data.get("totp", {}).get("key")

        if user_has_mfa:
            if not mfa_code:
                return SessionCreateStatus(success=False, mfa_required=True, code=None)

            totp_object: pyotp.TOTP = pyotp.TOTP(users.encryption.decrypt(user_mfa_key))
            is_valid = totp_object.verify(mfa_code)
            if not is_valid:
                return SessionCreateStatus(success=False, mfa_required=True, code=-1)

        session_id = Encryption.generate_random_string(SESSION_TOKEN_LENGTH)

        session = {
            "_id": Encryption.sha256(session_id),
            "expire": datetime.datetime.now() + datetime.timedelta(days=7),
            "ip": ip,
            "user-agent": user_agent,
            "owner-hash": Encryption.sha256(
                username + "frii.site"
            ),  # "frii.site" acts as a salt, making rainbow table attacts more difficult
            "username": Encryption(os.getenv("ENC_KEY")).encrypt(username),  # type: ignore[arg-type]
        }

        session_table.delete_in_time(date_key="expire")
        session_table.create_index("owner-hash")
        session_table.insert_document(session)

        users.modify_document(
            filter={
                "$and": [{"_id": username}, {"permissions.invite": {"$exists": False}}]
            },
            key="permission.invite",
            value=True,
            operation="$set",
            ignore_no_matches=True,
        )

        logger.debug(user_data.get("display-name")[:6])
        if user_data.get("display-name").startswith("gAAAAA") and real_username:
            logger.info("Updating display-name and username")
            users.table.update_one(
                {"_id": username},
                {
                    "$set": {
                        "display-name": users.encryption.encrypt(real_username),
                        "username": username,
                    }
                },
            )

        UserManager(
            users, ip, username
        ).start()  # updates `last-login` and `accessed-from` fields of user
        return SessionCreateStatus(success=True, mfa_required=False, code=session_id)

    def create_2fa(self) -> dict:
        if not self.valid:
            raise SessionError()

        key_for_user = pyotp.random_base32()

        backup_keys = [Encryption.generate_random_string(16) for _ in range(5)]
        encrypted_keys = [self.encryption.encrypt(key) for key in backup_keys]

        user_data = self.users_table.find_user({"_id": self.username})

        if user_data is None:
            raise UserNotExistError("User does not exist!")

        if user_data.get("totp", {}).get("verified"):
            return None

        self.users_table.modify_document(
            {"_id": self.username},
            key="totp",
            value={
                "key": self.encryption.encrypt(key_for_user),
                "verified": False,
                "recovery": encrypted_keys,
            },
            operation="$set",
        )

        setup_url: str = pyotp.totp.TOTP(
            key_for_user, interval=30, digits=6
        ).provisioning_uri(self.username, "frii.site")

        return {"url": setup_url, "codes": backup_keys}

    def verify_2fa(self, code: str):
        """Verifies that mfa code was succesfully created and set by the user"""
        if not self.user_cache_data.get("totp"):
            raise VerificationError("MFA not generated")

        if self.user_cache_data.get("totp", {}).get("verified"):
            raise ValueError("User is already verified")

        totp_object = pyotp.TOTP(
            self.encryption.decrypt(self.user_cache_data.get("totp", {}).get("key"))
        )

        is_valid = totp_object.verify(code)

        if is_valid:
            self.users_table.modify_document(
                {"_id": self.username},
                key="totp.verified",
                value=True,
                operation="$set",
            )

        return is_valid

    def check_backup_code_valid(self, user_code: str) -> bool:
        codes = self.user_cache_data.get("totp", {}).get("recovery", [])
        found_code: bool = False

        for code in codes:
            decrypted_code = self.encryption.decrypt(code)
            logger.debug(
                f"Checking mfa code {user_code[:4]}... to {decrypted_code[:4]}"
            )

            if user_code == decrypted_code:
                logger.debug("Found a matching code")
                found_code = True
                break

        return found_code

    def remove_mfa(self, backup_code: str | None, mfa_code: str | None):
        is_authenticated: bool = False
        if backup_code:
            logger.info("Checking backup code")
            is_authenticated = self.check_backup_code_valid(backup_code)
        elif mfa_code:
            logger.info("Checking mfa code")
            totp_object = pyotp.TOTP(
                self.encryption.decrypt(self.user_cache_data.get("totp", {}).get("key"))
            )
            is_authenticated = totp_object.verify(mfa_code)

        if not is_authenticated:
            raise ValueError("Invalid authentication")

        self.users_table.remove_key(
            {
                "_id": self.username,
            },
            "totp",
        )

    @staticmethod
    def clear_sessions(user_id: str, session_table: Sessions):
        """Deletes every sesion that user has. Used mainly for resetting the password"""

        session_table.delete_many(
            {"owner-hash": Encryption.sha256(user_id + "frii.site")}
        )

        return True

    def delete(self, id) -> bool:
        """Deletes a specific session.

        Arguements:
            self: being an instance of Session to authenticate that the person trying to delete the session actually has permissions to do so
            id: sha256 hash of the session_id, that will be deleted

        Throws:
            SessionError: target session does not exist
            SessionPermissionError: session does not belong to user
        """
        if not self.valid:
            return False

        data: dict | None = self.session_table.find_item({"_id": id})

        if data is None:
            raise SessionError("Session does not exist")

        session_username: str = self.encryption.decrypt(data["username"])

        if self.username != session_username:
            raise SessionPermissonError("Invalid username for session")

        self.session_table.delete_document({"_id": id})
        return True
