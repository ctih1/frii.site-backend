import os
import time
import logging
from typing import Any, List, TYPE_CHECKING, Literal
from typing_extensions import NotRequired, Dict, Required, TypedDict
from pymongo import MongoClient
from database.table import Table
import requests  # type: ignore[import-untyped]
import json
import datetime


from database.exceptions import (
    InviteException,
    EmailException,
    UsernameException,
    UserNotExistError,
)

from mail.email import Email
from security.encryption import Encryption
from security.session import NewSessionType, OldSessionType
from security.api import ApiType

if TYPE_CHECKING:
    from database.tables.domains import DomainFormat
    from database.tables.sessions import Sessions as SessionTable


logger: logging.Logger = logging.getLogger("frii.site")


class CountryType(TypedDict):
    ip: str
    hostname: NotRequired[str]
    city: str
    region: str
    country: str  # 2 char country code (ex. FI)
    loc: str  # latitude,longtitude
    org: str
    postal: str  # Zip code
    timezone: str  # TZ format (ex. Europe/Helsinki)
    country_name: str
    isEU: bool
    country_flag_url: str
    country_flag: dict  # contains keys "emoji", and "unicode", which you can probably guess what it does
    country_currency: dict  # contains keys "code", (ex. EUR), and symbol (ex. €)
    continent: dict  # contains keys "code", (ex. EU), and name, (ex. Europe)
    latitude: str
    longitude: str


class InviteType(TypedDict):
    used: bool
    used_by: NotRequired[str]
    used_at: NotRequired[int]  # epoch timestamp


MFA = TypedDict("MFA", {"verified": bool, "key": str, "recovery": List[str]})

UserPageType = TypedDict(
    "UserPageType",
    {
        "username": str,
        "email": str,
        "lang": str,
        "country": CountryType,
        "created": int,
        "verified": bool,
        "permissions": Dict[str, Any],
        "beta-enroll": bool,
        "sessions": List[NewSessionType | OldSessionType] | List[dict],
        "invites": Dict[str, InviteType],
        "mfa_enabled": bool,
    },
)

UserType = TypedDict(
    "UserType",
    {
        "_id": str,
        "email": str,
        "password": str,
        "display-name": str,
        "username": NotRequired[str],
        "lang": str,
        "country": CountryType,
        "email-hash": NotRequired[str],
        "accessed-from": NotRequired[List[str]],
        "created": int,  # Epoch timestamp
        "last-login": int,  # Epoch timestamp
        "permissions": dict,
        "verified": bool,
        "domains": Required[Dict[str, "DomainFormat"]],
        "feature-flags": NotRequired[Dict[str, bool]],
        "api-keys": NotRequired[Dict[str, ApiType]],
        "credits": NotRequired[int],
        "beta-enroll": NotRequired[bool],
        "beta-updated": NotRequired[int],
        "invites": NotRequired[Dict[str, InviteType]],
        "invite-code": NotRequired[str],
        "totp": NotRequired[MFA],
        "banned": NotRequired[Literal[True]],
        "ban-reasons": NotRequired[List[str]],
    },
)


class Users(Table):
    def __init__(self, mongo_client: MongoClient):
        super().__init__(mongo_client, "frii.site")
        self.encryption: Encryption = Encryption(os.getenv("ENC_KEY") or "none")

    def find_user(self, filter: dict, find_banned: bool = False) -> UserType | None:
        data: UserType = self.find_item(filter)  # type: ignore[return-value,assignment]
        if data and data.get("banned") and not find_banned:
            return None
        return data

    def find_users(self, filter: dict) -> List[UserType] | None:
        return self.find_items(filter)  # type: ignore[return-value]

    def send_discord_analytic_webhook(
        self,
        country: str,
        site_variant: Literal["canary.frii.site", "www.frii.site"] | str,
    ) -> None:
        start = time.time()
        requests.post(
            os.getenv("DC_WEBHOOK", ""),
            data=json.dumps(
                {
                    "content": None,
                    "embeds": [
                        {
                            "title": "New user signup",
                            "description": f":flag_{country.lower()}: A new user signed up on {site_variant} from {country}! :flag_{country.lower()}:",
                            "color": 31743,
                            "timestamp": datetime.datetime.now(datetime.timezone.utc)
                            .isoformat(timespec="milliseconds")
                            .replace("+00:00", "Z"),
                        }
                    ],
                    "attachments": [],
                }
            ),
            headers={"Content-Type": "application/json"},
        )
        logger.debug(time.time() - start)

    def create_user(
        self,
        username: str,
        password: str,
        email: str,
        language: str,
        country,
        time_signed_up,
        email_instance: Email,
        target_url: str,  # target_url should only be the hostname (e.g canary.frii.site, www.frii.site)
    ) -> str:

        logger.info(f"Creating user with username {username}")
        original_username: str = username

        hashed_username: str = Encryption.sha256(username)
        lowercase_hashed_username = Encryption.sha256(username.lower())

        hashed_password: str = Encryption.sha256(password)

        if email_instance.is_taken(email):
            logger.error("Email is already taken")
            raise EmailException("Email is already in use!")

        if (
            self.find_item(
                {
                    "$or": [
                        {"_id": hashed_username},
                        {"username": lowercase_hashed_username},
                    ]
                }
            )
            is not None
        ):
            raise UsernameException("Username already taken!")

        account_data: UserType = {
            "_id": hashed_username,
            "email": self.encryption.encrypt(email),
            "password": self.encryption.create_password(hashed_password),
            "display-name": self.encryption.encrypt(original_username),
            "username": lowercase_hashed_username,
            "lang": language,
            "country": country,
            "email-hash": Encryption.sha256(email + "supahcool"),
            "accessed-from": [],
            "created": time_signed_up,
            "last-login": round(time.time()),
            "permissions": {"max-domains": 3, "max-subdomains": 50, "invite": False},
            "feature-flags": {},
            "verified": False,
            "domains": {},
            "api-keys": {},
            "credits": 200,
        }

        self.insert_document(account_data)
        self.create_index("username")

        if not email_instance.send_verification_code(
            target_url, hashed_username, email
        ):
            logger.info("Failed to send verification")
            raise EmailException("Email already in use!")

        try:
            self.send_discord_analytic_webhook(country["country"], target_url)
        except Exception as e:
            logger.error(e)

        return hashed_username

    def create_invite(self, user_id: str) -> str:
        logger.info("Creating invite...")
        invite_code: str = Encryption.generate_random_string(16)
        invite_user: UserType | None = self.find_user({"_id": user_id})

        if invite_user is None:
            raise UserNotExistError("User does not exist!")

        if len(invite_user.get("invites", {})) >= 3:
            logger.info("User has surprassed their invite limit")
            raise InviteException("Invite limit exceeded")

        self.table.update_one(
            {"_id": user_id},
            {
                "$set": {
                    f"invites.{invite_code}": {
                        "used": False,
                        "used_by": None,
                        "used_at": None,
                        "created": round(time.time()),
                    }
                }
            },
        )

        return invite_code

    def get_invites(self, user_id: str) -> Dict[str, InviteType] | dict:
        """Get user's invites.
        Returns empty dict if no invites are found
        Raises ValueError if user does not exist
        """
        user_data: UserType | None = self.find_user({"_id": user_id})

        if user_data is None:
            raise UserNotExistError("Invalid user!")

        return user_data.get("invites", {})

    def get_user_gdpr(self, user_id: str) -> dict:
        user_data: UserType | None = self.find_user({"_id": user_id})

        if user_data is None:
            raise UserNotExistError("Invalid user")

        return {
            "user_id": user_data["_id"],
            "location": user_data["country"],
            "creation_date": user_data["created"],
            "domains": user_data["domains"],
            "lang": user_data["lang"],
            "last_login": user_data["last-login"],
            "permissions": user_data["permissions"],
            "verified": user_data["verified"],
        }

    def get_user_profile(
        self, user_id: str, session_table: "SessionTable", find_banned: bool = False
    ) -> UserPageType:
        logger.info(f"Getting user profile for {user_id}")
        user_data: UserType | None = self.find_user({"_id": user_id}, find_banned)

        if user_data is None:
            raise UserNotExistError("Invalid user")

        # Two different filters because in the middle of migrating the session to JWTs
        session_data = session_table.find_items(
            {
                "$or": [
                    {"owner-hash": Encryption.sha256(user_id + "frii.site")},
                    {"$and": [{"owner": user_id}, {"type": "refresh"}]},
                ]
            }
        )  # type: ignore[assignment]

        for session in session_data:
            # NOTE: If you're an admin and want to make a session last forever, this cant handle much lol
            # I tried using 3025 and `.timestamp()` just errored out
            if session.get("expire"):
                logger.debug("Found old schema session")
                session["expires"] = round(session.get("expire").timestamp())  # type: ignore[union-attr]
                del session["expire"]

            elif session.get("expires"):
                logger.debug("Found new schema session")
                session["expires"] = round(session.get("expires").timestamp())  # type: ignore[union-attr]

        return {
            "username": self.encryption.decrypt(user_data["display-name"]),
            "email": self.encryption.decrypt(user_data["email"]),
            "lang": user_data["lang"],
            "country": user_data["country"],
            "created": user_data["created"],
            "verified": user_data["verified"],
            "permissions": user_data.get("permissions", {}),
            "beta-enroll": user_data.get("beta-enroll", False),
            # conversts datetime object of expire date in db to linux epoch int. fastapi's json encoder doesnt like datetime objects
            "sessions": session_data,  # type: ignore[typeddict-item]
            "invites": user_data.get("invites", {}),  # type: ignore[typeddict-item]
            "mfa_enabled": user_data.get("totp", {}).get("verified", False),
        }

    def change_beta_enrollment(self, user_id: str, mode: bool = False) -> None:
        self.modify_document({"_id": user_id}, "$set", "beta-enroll", mode)
        self.modify_document(
            {"_id": user_id}, "$set", "beta-updated", round(time.time())
        )

    def mark_deletion_pending(self, userid: str, reasons: List[str]) -> None:
        self.table.update_one(
            {"_id": userid},
            {
                "$set": {
                    "banned": True,
                    "deleted-in": datetime.datetime.now()
                    + datetime.timedelta(weeks=52),
                },
                "$push": {"ban-reasons": {"$each": reasons}},
            },
        )
        self.delete_in_time("deleted-in")
