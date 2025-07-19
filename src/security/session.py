from __future__ import annotations
from typing import List, TYPE_CHECKING, Literal
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
from enum import Enum
import jwt
from jwt import ExpiredSignatureError, InvalidSignatureError, DecodeError
import secrets

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
    "SessionCreateStatus",
    {
        "success": bool,
        "mfa_required": bool,
        "refresh_token": str | None,
        "access_token": str | None,
    },
)

from typing import TypedDict, Literal


class InvalidToken(Enum):
    expired = 0
    invalid = 1


class AccessTokenData(TypedDict):
    type: Literal["access"]
    sub: str  # Username or user ID
    exp: int  # Expiration timestamp (Unix)
    iat: int  # Issued at timestamp (Unix)
    jti: str  # Unique token ID
    iss: Literal["https://api.frii.site"]
    aud: Literal["www.frii.site"]


class RefreshTokenData(TypedDict):
    type: Literal["refresh"]
    sub: str
    exp: int
    iat: int
    jti: str
    iss: Literal["https://api.frii.site"]
    aud: Literal["www.frii.site"]


REFRESH_AMOUNT = 14 * 60 * 60 * 24


OldSessionType = TypedDict(
    "OldSessionType", {"user-agent": str, "ip": str, "expires": int, "id": str}
)
NewSessionType = TypedDict(
    "NewSessionType",
    {
        "owner": str,
        "type": Literal["refresh", "access"],
        "created": int,
        "expires": int,
        "agent": str,
        "ip": str,
    },
)

logger: logging.Logger = logging.getLogger("frii.site")


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


class Session:
    def __init__(self, access_token: str, users: Users, sessions: Sessions) -> None:
        """Creates a Session object.
        Arguements:
            session_id: Access token found in X-Auth-Token
            users: Instance of the user table
            sessions: Instance of the session table
        """
        self.session_table: Sessions = sessions
        self.users_table: Users = users
        self.encryption: Encryption = Encryption(os.getenv("ENC_KEY"))  # type: ignore[arg-type]

        self.token = access_token
        self.token_result: AccessTokenData | InvalidToken = Session.__get_payload(self.token, "access")  # type: ignore

        self.valid: bool = True
        self.expired: bool = False

        if isinstance(self.token_result, InvalidToken):
            logger.info("Token is not valid!")
            self.valid = False
            if self.token_result == InvalidToken.expired:
                logger.info("Token has expired.")
                self.expired = True
        else:
            self.data: AccessTokenData = self.token_result
            if not self.session_table.get_session(self.data["jti"]):
                logger.info(f"Couldnt find session {self.data['jti']} in db")
                self.valid = False

        self.username: str = "" if not self.valid else self.data["sub"]
        self.user_id = self.username

        self.user_cache_data: UserType = self.__user_cache()
        self.permissions: list = self.__get_permimssions()
        self.flags: list = self.__get_flags()

        threading.Thread(target=self.__perform_migrations).start()

    def __user_cache(self) -> UserType:
        """
        Caches the user data of the session. You should use session.user_cache for every query,
        as user_cache gets reset everytime a session object is created, aka it refreshes every request
        """
        if not self.valid:
            return {}  # type: ignore[typeddict-item]
        data: UserType | None = self.users_table.find_user({"_id": self.data["sub"]})

        if data is None:
            self.valid = False
            return {}  # type: ignore[typeddict-item]

        return data

    def __perform_migrations(self) -> None:
        if not self.user_cache_data["_id"]:
            logger.info("Skipping migrations invalid data")
            return

        logger.info("Starting migrations")

        repaired_domains = {}
        domains_fixed: int = 0
        for domain, data in self.user_cache_data["domains"].items():
            if domain.lower() != domain:
                logger.info("Detected domain that isnt lowercase")
                domains_fixed += 1

            repaired_domains[domain.lower()] = data

        if (
            len(repaired_domains) > 0
            and len(repaired_domains) == self.user_cache_data["domains"]
        ):
            logger.info(f"Fixed {domains_fixed} out of {len(repaired_domains)} domains")

            self.users_table.modify_document(
                {"_id": self.username}, "$set", "domains", repaired_domains
            )
            self.user_cache_data["domains"] = repaired_domains

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

    @staticmethod
    def __get_payload(
        token: str, type: Literal["any", "refresh", "access"] = "any"
    ) -> AccessTokenData | RefreshTokenData | InvalidToken:
        """
        Gets the payload insided the JWT token. Returns InvalidToken enum if toke nis inalid in some way
        """
        try:
            data = jwt.decode(
                token,
                os.environ.get("JWT_KEY") or "",
                algorithms=["HS256"],
                audience="www.frii.site",
                issuer="https://api.frii.site",
            )

            if data["type"] != type and type != "any":
                raise ValueError("Invalid type")

            return data
        except InvalidSignatureError:
            logger.error("Invalid key")
            return InvalidToken.invalid
        except ExpiredSignatureError:
            logger.error("Refresh required")
            return InvalidToken.expired
        except DecodeError:
            logger.error("Decode error in key")
            return InvalidToken.invalid

    @staticmethod
    def refresh(
        refresh_token: str, session_table: Sessions, user_agent: str, ip: str
    ) -> tuple[str, str] | Literal[False]:
        """
        Deletes the old refresh + access token, and replaces them with new ones.
        Refresh token expiration date resets to 14 days from now

        """
        token_data = Session.__get_payload(refresh_token, "refresh")

        if isinstance(token_data, InvalidToken):
            logger.error("Invalid token!")
            return False

        if token_data.get("type") != "refresh":
            logger.error("Invalid token type")
            return False

        target_session = session_table.get_session(token_data["jti"])
        if target_session is None:
            logger.error(f"Token {token_data['jti']} has been nuked already")
            return False

        delete_thread = threading.Thread(
            target=session_table.delete_session_pair, args=(token_data["jti"],)
        )
        delete_thread.start()

        access_token, refresh_token = Session.create_session_pair(
            token_data["sub"], user_agent, ip, session_table
        )

        delete_thread.join()
        return access_token, refresh_token

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
            username (str): The userid of the user.
            mfa_code (str): a possible mfa code for the users account
            ip (str): The IP address of the user.
            user_agent (str): The user agent string of the user's browser.
            users (Users): An instance of the Users class for database operations.
            session_table (Sessions): An instance of the Sessions class for session management.
        Returns:
            SessionCreateStatus: An object indicating the success of the session creation,
                                    whether multi-factor authentication (MFA) is required,
                                    and a refresh and access token if successful
        """

        user_data: UserType | None = users.find_user({"_id": username})

        if user_data is None:
            raise UserNotExistError()

        user_has_mfa = user_data.get("totp", {}).get("verified")
        user_mfa_key = user_data.get("totp", {}).get("key")

        if user_has_mfa:
            if not mfa_code:
                return SessionCreateStatus(
                    success=False,
                    mfa_required=True,
                    access_token=None,
                    refresh_token=None,
                )

            totp_object: pyotp.TOTP = pyotp.TOTP(users.encryption.decrypt(user_mfa_key))  # type: ignore[arg-type]
            is_valid = totp_object.verify(mfa_code)
            if not is_valid:
                if totp_object.verify(
                    mfa_code, datetime.datetime.now() - datetime.timedelta(seconds=15)
                ):
                    is_valid = True
                else:
                    return SessionCreateStatus(
                        success=False,
                        mfa_required=True,
                        access_token=None,
                        refresh_token=None,
                    )

        access_token, refresh_token = Session.create_session_pair(
            username, user_agent, ip, session_table
        )

        if real_username and (
            not user_data.get("display-name")
            or user_data.get("display-name").startswith("gAAAAA")  # type: ignore[union-attr]
        ):
            logger.info("Updating display-name and username")
            users.table.update_one(
                {"_id": username},
                {
                    "$set": {
                        "display-name": users.encryption.encrypt(real_username),
                        "username": Encryption.sha256(real_username.lower()),
                    }
                },
            )

        UserManager(
            users, ip, username
        ).start()  # updates `last-login` and `accessed-from` fields of user
        return SessionCreateStatus(
            success=True,
            mfa_required=False,
            access_token=access_token,
            refresh_token=refresh_token,
        )

    @staticmethod
    def create_session_pair(
        username: str, user_agent: str, ip: str, session_table: Sessions
    ) -> tuple[str, str]:
        """Creates a refresh and access token pair.
        This function is also used for refreshing tokens.
        This function should only be run after you've authenticated the user in some way.
        No built in authentication for this one.
        """
        now: int = round(time.time())

        access_data = {
            "type": "access",
            "sub": username,
            "exp": now + 600,
            "iat": now - 1,
            "jti": secrets.token_hex(16),
            "iss": "https://api.frii.site",
            "aud": "www.frii.site",
        }

        refresh_data = {
            "type": "refresh",
            "sub": username,
            "exp": now + REFRESH_AMOUNT,
            "iat": now - 1,
            "jti": secrets.token_hex(16),
            "iss": "https://api.frii.site",
            "aud": "www.frii.site",
        }

        secret = os.environ.get("JWT_KEY") or ""

        access_token: str = jwt.encode(access_data, secret, algorithm="HS256")
        refresh_token: str = jwt.encode(refresh_data, secret, algorithm="HS256")

        def submit_into_db():
            logger.info("Sending sessions into db")
            session_table.add_session(
                access_data["jti"],
                username,
                access_data["type"],
                access_data["exp"],
                user_agent,
                ip,
                parent=refresh_data["jti"],
            )
            session_table.add_session(
                refresh_data["jti"],
                username,
                refresh_data["type"],
                refresh_data["exp"],
                user_agent,
                ip,
            )

        submit_into_db()

        return access_token, refresh_token

    @staticmethod
    def clear_sessions(user_id: str, session_table: Sessions):
        """Deletes every sesion that user has. Used mainly for resetting the password"""
        session_table.delete_many({"owner": user_id})

        return True

    def delete(self, id) -> bool:
        """Deletes a specific session.

        Arguements:
            self: being an instance of Session to authenticate that the person trying to delete the session actually has permissions to do so
            id: jwt id of the session. Can be access or refresh, both are handled
        """
        if not self.valid:
            return False

        session_data = self.session_table.get_session(id)

        if session_data is None:
            raise ValueError("Session not found!")

        success: bool = False

        if session_data.get("type") == "refresh":
            success = self.session_table.delete_session_pair(
                session_data.get("_id", "")
            )
        if session_data.get("type") == "access":
            success = self.session_table.delete_session_pair(
                session_data.get("parent", "")  # type: ignore[arg-type]
            )
        else:
            logger.warning("Old sesssion schema found")
            success = self.session_table.delete_document({"_id": id}) > 0

        return success

    def create_2fa(self) -> dict:
        """Starts 2FA setup, creats backup keys, and the key itself.
        Users have to verify their 2fa setup (self.verify_2fa) with a seperate request
        to confirm that they have correctly setup 2fa.

        Until 2fa is verified, mfa will not be enforced on login
        """
        if not self.valid:
            raise SessionError()

        key_for_user = pyotp.random_base32()

        backup_keys = [Encryption.generate_random_string(16) for _ in range(5)]
        encrypted_keys = [self.encryption.encrypt(key) for key in backup_keys]

        user_data = self.users_table.find_user({"_id": self.username})

        if user_data is None:
            raise UserNotExistError("User does not exist!")

        if user_data.get("totp", {}).get("verified"):
            raise ValueError("Used already has 2FA")

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

        display_name = self.encryption.decrypt(self.user_cache_data["display-name"])
        setup_url: str = pyotp.totp.TOTP(
            key_for_user, interval=30, digits=6
        ).provisioning_uri(display_name, "frii.site")

        return {"url": setup_url, "codes": backup_keys}

    def verify_2fa(self, code: str):
        """Verifies that mfa code was succesfully created and set by the user.
        After verification is done, MFA is necessary to login
        """
        if not self.user_cache_data.get("totp"):
            raise VerificationError("MFA not generated")

        if self.user_cache_data.get("totp", {}).get("verified"):
            raise ValueError("User is already verified")

        user_key = self.user_cache_data.get("totp", {}).get("key")
        if user_key is None:
            raise ValueError("user does not have a key?")
        totp_object = pyotp.TOTP(self.encryption.decrypt(user_key))

        is_valid = totp_object.verify(code)

        if is_valid:
            self.users_table.modify_document(
                {"_id": self.username},
                key="totp.verified",
                value=True,
                operation="$set",
            )

        return is_valid

    def check_code(self, code: str) -> bool:
        """Checks if a backup or 2fa code is valid"""
        try:
            mfa_code = int(code)
            return self.check_mfa_valid(str(mfa_code))
        except ValueError:
            return self.check_backup_code_valid(code)

    def check_mfa_valid(self, code: str) -> bool:
        totp_object = pyotp.TOTP(
            self.encryption.decrypt(self.user_cache_data.get("totp", {}).get("key"))  # type: ignore[arg-type]
        )
        return totp_object.verify(code)

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
            is_authenticated = self.check_mfa_valid(mfa_code)
        if not is_authenticated:
            raise ValueError("Invalid authentication")

        self.users_table.remove_key(
            {
                "_id": self.username,
            },
            "totp",
        )

    @staticmethod
    def remove_mfa_static(
        userid: str, user_table: Users, user: UserType, backup_code: str
    ):
        """
        Removes MFA without a session object. Used for when user removes 2fa with a backup code
        """
        logger.info("Checking backup code")
        codes = user.get("totp", {}).get("recovery", [])
        found_code: bool = False

        for code in codes:
            decrypted_code = user_table.encryption.decrypt(code)
            logger.debug(
                f"Checking mfa code {backup_code[:4]}... to {decrypted_code[:4]}"
            )

            if backup_code == decrypted_code:
                logger.debug("Found a matching code")
                found_code = True
                break

        if not found_code:
            raise ValueError("Invalid backup code")

        user_table.remove_key(
            {
                "_id": userid,
            },
            "totp",
        )

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
            target: Session | None = Session.find_session_instance(args, kwargs)
            if not target or not target.valid:
                raise SessionError("Session is not valid (requires auth)")
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
                target: Session | None = Session.find_session_instance(args, kwargs)
                if not target or not target.valid:
                    raise SessionError("Session is not valid (requires permission)")
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
                target: Session | None = Session.find_session_instance(args, kwargs)
                if not target or not target.valid:
                    raise SessionError("Session is not valid (flag missing)")
                if flag not in target.flags:
                    raise SessionFlagError(f"User is missing flag {flag}")
                a = func(*args, **kwargs)
                return a

            return wrapper

        return decor
