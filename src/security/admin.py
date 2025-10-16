import os
from typing import List, Dict
from typing_extensions import TypedDict
from security.session import Session
from security.encryption import Encryption
from database.tables.users import Users
from database.tables.users import UserType, UserPageType
from database.tables.domains import Domains, DomainFormat
from database.tables.sessions import Sessions
from dns_.dns import DNS
from dns_.types import AVAILABLE_TLDS
from dns_.exceptions import DNSException
from mail.email import Email
from database.exceptions import UserNotExistError, FilterMatchError
import time

import logging


class DomainDeletionError(Exception): ...


class GenericDeletionError(Exception): ...


class AccountData(UserPageType):
    domains: Dict[str, DomainFormat]
    id: str
    banned: bool
    ban_reasons: List[str] | List[List[str]] | None
    last_login: int
    api_key_amount: int
    accessed_from: List[str]


logger: logging.Logger = logging.getLogger("frii.site")


class Admin:
    def __init__(
        self,
        users_table: Users,
        sessions_table: Sessions,
        domains: Domains,
        dns: DNS,
        mail: Email,
    ):
        self.users = users_table
        self.domains = domains
        self.dns = dns
        self.email = mail
        self.sessions = sessions_table

    def ban_user(self, reasons: List[str], user_data: UserType) -> bool:
        if len(reasons) == 0:
            raise ValueError("You need to specify atleast one ban reason")

        domains = {
            k.replace("[dot]", "."): v["type"] for k, v in user_data["domains"].items()
        }

        success = self.dns.delete_multiple(domains)
        if not success:
            logger.critical(
                "Domain mass deletion failed! Continuing with account deletion."
            )
            raise DomainDeletionError("Could not delete users domain")

        self.users.mark_deletion_pending(user_data["_id"], reasons)

        user_email: str = self.users.encryption.decrypt(user_data["email"])
        self.email.send_ban_email(user_email, reasons)

        return True

    def reinstate_user(self, user_id: str):
        user_data: UserType | None = self.users.find_user(
            {"_id": user_id}, find_banned=True
        )

        if not user_data:
            return UserNotExistError("User not found!")
        if not user_data.get("banned", False):
            return ValueError("User is not banned!")

        self.users.table.update_one(
            {"_id": user_id},
            {
                "$set": {"banned": False, "unbanned": round(time.time())},
                "$unset": {"deleted-in": 1},
            },
        )

        domains = {k.replace("[dot]", "."): v for k, v in user_data["domains"].items()}

        self.dns.register_multiple(domains, user_id)

    def find_user_by_domain(self, domain: str) -> AccountData | None:
        user_data = self.users.find_user(
            {f"domains.{Domains.clean_domain_name(domain)}": {"$exists": True}},
            find_banned=True,
        )

        if not user_data:
            logger.info("Failed to find user")
            return None

        return self.get_user_details_by_id(user_data["_id"])

    def find_by_username(self, username: str) -> AccountData | None:
        """
        ALmost the same as get_user_details_by_id, but usernames are not case sensitive
        """

        user: UserType | None = self.users.find_user(
            {
                "$or": [
                    {"_id": Encryption.sha256(username)},
                    {"username": Encryption.sha256(username.lower())},
                ]
            }
        )

        if not user:
            return None

        return self.get_user_details_by_id(user["_id"])

    def get_user_details_by_id(self, user_id: str) -> AccountData | None:
        user_profile: UserPageType | None = self.users.get_user_profile(
            user_id, self.sessions, True
        )

        if not user_profile:
            logger.info("User profile did not yield results")
            return None

        user_data: UserType | None = self.users.find_user({"_id": user_id}, True)

        if user_data is None:
            raise ValueError("Could not get user from db")

        account_data: AccountData = user_profile  # type: ignore[assignment]
        account_data["domains"] = user_data["domains"]
        account_data["id"] = user_data["_id"]
        account_data["banned"] = user_data.get("banned", False)
        account_data["ban_reasons"] = user_data.get("ban-reasons")
        account_data["last_login"] = round(user_data.get("last-login", 0))
        account_data["created"] = round(user_data.get("created", 0))
        account_data["api_key_amount"] = len(user_data.get("api-keys", []))
        account_data["accessed_from"] = list(set(user_data.get("accessed-from", [])))[
            :50
        ]

        return account_data

    def change_permission(
        self, user_id: str, permission: str, new_value: str | bool | int
    ) -> bool:
        logger.info(f"Changing user permission {permission}->{new_value}")
        try:
            self.users.modify_document(
                {"_id": user_id}, "$set", f"permissions.{permission}", new_value
            )
            return True
        except FilterMatchError:
            return False

    def add_domain(self, user_id: str, tld: AVAILABLE_TLDS):
        """Adds domain to TLDs

        :param user_id: id of the user
        :type user_id: str
        :param tld: the tld (without the . prefix)
        :type tld: AVAILABLE_TLDS
        """
        self.users.modify_document({"_id": user_id}, "$push", "owned-tlds", tld)

    def remove_domain(self, user_id: str, tld: AVAILABLE_TLDS):
        """Removes a TLD

        :param user_id: id of the user
        :type user_id: str
        :param tld: the tld (without . prefix)
        :type tld: AVAILABLE_TLDS
        """
        self.users.modify_document({"_id": user_id}, "$pull", "owned-tlds", tld)

    def verify(self, user_id: str):
        self.users.modify_document({"_id": user_id}, "$set", "verified", True)
