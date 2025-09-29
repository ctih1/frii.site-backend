from typing import Dict, List, TYPE_CHECKING
from typing_extensions import NotRequired, TypedDict
import time
import logging
from threading import Thread
from pymongo import MongoClient
from database.table import Table
import json
import re

if TYPE_CHECKING:
    from database.tables.users import Users, UserType

from database.exceptions import (
    UserNotExistError,
    ConflictingReferralCode,
    UserConflictError,
)

logger: logging.Logger = logging.getLogger("frii.site")


ReferralType = TypedDict(
    "ReferralType", {"_id": str, "owner": str, "users": List[str], "created": int}
)


class Referrals(Table):
    def __init__(self, mongo_client: MongoClient, users: "Users"):
        super().__init__(mongo_client, "referrals")
        self.users: "Users" = users

    def insert(self, document: ReferralType) -> None:
        return super().insert_document(document)

    def create(self, user_id: str, requested_code: str) -> None:
        logger.info("Creating referral code")
        if len(requested_code) < 3 or len(requested_code) > 50:
            raise ValueError(
                f"requested code is too long or too short! {requested_code}"
            )

        if not re.fullmatch("[a-zA-Z0-9-]+", requested_code):
            raise ValueError("Invalid code regex!")

        lookup_request_code: str = self.users.encryption.sha256(requested_code)

        user: "UserType | None" = self.users.find_user({"_id": user_id})

        if user is None:
            raise UserNotExistError("User does not exist!")

        if user.get("referral-code") is not None:
            raise ValueError("User already has a referral code")

        if self.find_item({"_id": lookup_request_code}) is not None:
            raise ConflictingReferralCode("Referral code already exists!")

        self.insert(
            {
                "_id": lookup_request_code,
                "owner": user_id,
                "users": [],
                "created": round(time.time()),
            }
        )

        self.users.modify_document(
            {"_id": user_id}, "$set", "referral-code", requested_code
        )

    def check(self, referral_code: str) -> bool:
        lookup_request_code: str = self.users.encryption.sha256(referral_code)

        referral: ReferralType | None = self.find_item({"_id": lookup_request_code})  # type: ignore
        return referral is not None

    def use(self, user: "UserType", referral_code: str):
        """Uses referral code. Does NOT modify the referred user directly, please handle that yourself

        :param user: the user who got referred
        :type user: UserType
        :param referral_code: the referral code
        :type referral_code: str
        :raises ValueError: if referral code isnt valid
        """
        logger.info(f"Using referral {referral_code}")
        lookup_request_code: str = self.users.encryption.sha256(referral_code)

        referral: ReferralType | None = self.find_item({"_id": lookup_request_code})  # type: ignore

        if referral is None:
            logger.warning("Referral does not exist!")
            raise ValueError("Referral does not exist!")

        logger.info(f"Updating user {referral['owner']} max domains")
        self.users.table.update_one(
            {"_id": referral["owner"]},
            {"$inc": {"permissions.max-domains": 1, "referred-count": 1}},
        )

        self.modify_document({"_id": referral["_id"]}, "$push", "users", user["_id"])

    def find_user_and_append(self, user_id: str, list: List["UserType | None"]) -> None:
        list.append(self.users.find_user({"_id": user_id}))

    def get_users(self, referral_code: str) -> List["UserType"]:
        referrals: List["UserType"] = self.find_items({"referred-by": referral_code})  # type: ignore

        return referrals
