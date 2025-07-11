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
from dns_.exceptions import DNSException
from mail.email import Email
from database.exceptions import UserNotExistError, FilterMatchError
import time

import logging


class DomainDeletionError(Exception): ...


class GenericDeletionError(Exception): ...


class AccountData(TypedDict, UserPageType):
    domains: Dict[str, DomainFormat]
    id: str
    banned: bool
    ban_reasons: List[str]
    last_login: int


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
            {f"domains.{domain}": {"$exists": True}}, find_banned=True
        )
        if user_data is None:
            return None

        user_page_data = self.users.get_user_profile(
            user_data["_id"], self.sessions, True
        )

        if user_page_data is None:
            logger.warning("Couldnt find in second stage?")
            return None

        account_data: AccountData = user_page_data  # type: ignore[assignment]
        account_data["domains"] = user_data["domains"]
        account_data["id"] = user_data["_id"]
        account_data["banned"] = user_data.get("banned", False)
        account_data["ban_reasons"] = user_data.get("ban-reasons", [])
        account_data["last_login"] = user_data.get("last-login", 0)

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
