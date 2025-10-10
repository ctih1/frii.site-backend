from typing import List, Annotated, Literal
import os
import logging
from fastapi import APIRouter, Request, Header, Depends, Form
from fastapi.exceptions import HTTPException
from starlette.datastructures import FormData
from fastapi.responses import JSONResponse
from server.routes.models.blog import BlogType
from database.tables.blogs import Blogs
from database.tables.users import Users
from database.tables.reward_codes import Rewards
from database.tables.sessions import Sessions
from database.exceptions import UserNotExistError, InviteException
from security.session import Session
from security.convert import Convert
from mail.email import Email
import json

logger: logging.Logger = logging.getLogger("frii.site")


PURCHASE_TYPE = Literal["Donation", "Subscription", "Commission", "Shop Order"]
EXTRA_DOMAIN_LINK_CODE = "65a532e32b"


class Kofi:
    def __init__(self, emails: Email, rewards_table: Rewards) -> None:
        self.router = APIRouter(prefix="/kofi")
        self.emails: Email = emails
        self.rewards: Rewards = rewards_table

        self.router.add_api_route(
            "/webhook",
            self.webhook,
            methods=["POST"],
            responses={
                200: {"description": "Succesfully registered event"},
                401: {"description": "Invalid verification token passed"},
            },
            tags=["kofi"],
        )

        logger.info("Initialized")

    def webhook(self, request: Request, data: Annotated[str, Form()]) -> None:
        jason = json.loads(data)
        logger.info(json.dumps(jason, indent=2))

        if jason.get("verification_token") != os.environ.get("KOFI_VERIFICATION_TOKEN"):
            logger.warning("Verification code did not match the kofi verification code")
            raise HTTPException(status_code=401, detail="Invalid verification code")

        purchase_type: PURCHASE_TYPE | None = jason.get("type")  # type: ignore[assignment]

        if purchase_type is None:
            logger.warning("Purchase type not specified")
            raise HTTPException(
                status_code=422, detail="Form data did not pass a purchase type"
            )

        email: str | None = jason.get("email")  # type: ignore[assignemnt]
        if email is None:
            logger.error("Email not specified")
            raise HTTPException(
                status_code=422, detail="Form data did not pass an email"
            )

        logger.info("Recieved webhook from Kofi")

        increased_subdomains: int = 0
        increased_domains: int = 0

        code: str | None = None

        if purchase_type == "Shop Order":
            for item in jason.get("shop_items"):
                if item.get("direct_link_code") == EXTRA_DOMAIN_LINK_CODE:
                    quantity: int = item.get("quantity", 1)
                    increased_domains = 10 * quantity
                    increased_subdomains = 100 * quantity

            code = self.rewards.create(
                email,
                {
                    "$inc": {
                        "permissions.max-domains": increased_domains,
                        "permissions.max-subdomains": increased_subdomains,
                    }
                },
            )

        if code is None:
            raise HTTPException(
                status_code=422, detail="Invalid purchase type specified"
            )

        self.emails.send_purchase_confirmation(
            email, f"https://canary.frii.site/redeem?c={code}"
        )
