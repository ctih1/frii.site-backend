from typing import List, Annotated, get_args
import time
import logging
from fastapi import APIRouter, Request, Header, Depends
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from server.routes.models.blog import BlogType
from database.tables.blogs import Blogs
from database.tables.users import Users, UserType, UserPageType
from database.tables.sessions import Sessions
from database.exceptions import UserNotExistError, InviteException
from mail.email import Email
from dns_.exceptions import DNSException
from dns_.types import AVAILABLE_TLDS
from security.session import Session
from security.encryption import Encryption
from security.convert import Convert
from security.admin import Admin as AdminTools, DomainDeletionError, AccountData
from server.routes.models.admin import BanUser

converter: Convert = Convert()
logger: logging.Logger = logging.getLogger("frii.site")


class Admin:
    def __init__(
        self,
        user_table: Users,
        session_table: Sessions,
        admin: AdminTools,
    ) -> None:
        converter.init_vars(user_table, session_table)

        self.router = APIRouter(prefix="/admin")
        self.admin_tools = admin
        self.sessions = session_table
        self.users = user_table

        self.router.add_api_route(
            "/domain/delete",
            self.delete_domain,
            methods=["DELETE"],
            responses={
                200: {"description": "Domain deleted"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/reinstate",
            self.reinstate_user,
            methods=["POST"],
            responses={
                200: {"description": "User reinstated"},
                404: {"description": "User not found"},
                412: {"description": "User already unbanned"},
                503: {"description": "Failed to recover DNS records"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/verify",
            self.verify,
            methods=["POST"],
            responses={
                200: {"description": "User verified"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/tld/add",
            self.add_tld,
            methods=["POST"],
            responses={
                200: {"description": "TLD added"},
                412: {"description": "Invalid TLD"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/tld/remove",
            self.remove_tld,
            methods=["POST"],
            responses={
                200: {"description": "TLD added"},
                412: {"description": "Invalid TLD"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/can-access",
            self.can_access,
            methods=["GET"],
            responses={
                200: {"description": "User can access the admin panel"},
                403: {"description": "User cant access the admin panel"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/delete",
            self.delete_user,
            methods=["DELETE"],
            responses={
                200: {"description": "User deleted"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/get/domain",
            self.find_user_by_domain,
            methods=["GET"],
            responses={
                200: {"description": "User found"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/delete/record",
            self.delete_dns_record,
            methods=["DELETE"],
            responses={
                200: {"description": "User found"},
                503: {"description": "Failed to delete record"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/get/id",
            self.find_user_by_id,
            methods=["GET"],
            responses={
                200: {"description": "User found"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/get/username",
            self.find_user_by_username,
            methods=["GET"],
            responses={
                200: {"description": "User found"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/get/email",
            self.find_user_by_email,
            methods=["GET"],
            responses={
                200: {"description": "User found"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/get/referral",
            self.find_user_by_referral,
            methods=["GET"],
            responses={
                200: {"description": "User found"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/permission",
            self.change_permission,
            methods=["PATCH"],
            responses={
                200: {"description": "Permission changed"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        logger.info("Initialized")

    @Session.requires_auth
    @Session.requires_permission(permission="account")
    def delete_user(self, body: BanUser, session: Session = Depends(converter.create)):
        user_data: UserType | None = self.users.find_user({"_id": body.user_id})
        if user_data is None:
            raise HTTPException(status_code=404, detail="User not found")

        try:
            status = self.admin_tools.ban_user(body.reasons, user_data)
        except DomainDeletionError:
            raise HTTPException(status_code=503, detail="Failed to delete domains")

        if not status:
            raise HTTPException(500, detail="Failed to delete user")

    @Session.requires_auth
    @Session.requires_permission(permission="account")
    def reinstate_user(
        self, user_id: str, session: Session = Depends(converter.create)
    ):
        try:
            self.admin_tools.reinstate_user(user_id)
        except UserNotExistError:
            raise HTTPException(status_code=404, detail="User not found")
        except ValueError:
            raise HTTPException(status_code=412, detail="User not banneds")
        except DNSException:
            raise HTTPException(status_code=503, detail="Failed to recover DNS records")

    @Session.requires_auth
    @Session.requires_permission(permission="account")
    def delete_domain(
        self,
        domain: str,
        userid: str,
        reason: str,
        session: Session = Depends(converter.create),
    ):
        target_user = self.admin_tools.get_user_details_by_id(userid)
        if not target_user:
            raise HTTPException(status_code=404, detail="Couldnt find a user")

        email: str = target_user["email"]

        dns_success = self.admin_tools.dns.delete_domain(
            self.admin_tools.domains.beautify_domain_name(domain),
            target_user["domains"][self.admin_tools.domains.clean_domain_name(domain)][
                "type"
            ],
        )

        if dns_success:
            if self.admin_tools.domains.delete_domain(userid, domain):
                self.admin_tools.email.send_domain_termination_email(
                    email, self.admin_tools.domains.beautify_domain_name(domain), reason
                )
                logger.info(f"Deleted domain {domain}")
            else:
                logger.warning("Failed to delete domain (DB)")
        else:
            logger.warning("Failed to delete domain (DNS)")
            raise HTTPException(status_code=500, detail="Failed to delete domain")

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_domain(
        self, domain: str, session: Session = Depends(converter.create)
    ) -> AccountData:
        user_profile: AccountData | None = self.admin_tools.find_user_by_domain(domain)
        if user_profile is None:
            raise HTTPException(status_code=404, detail="User not found")

        return user_profile

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_referral(
        self, referral: str, session: Session = Depends(converter.create)
    ) -> AccountData:
        user_profile: AccountData | None = self.admin_tools.find_by_referral(referral)
        if user_profile is None:
            raise HTTPException(status_code=404, detail="User not found")

        return user_profile

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_email(
        self, email: str, session: Session = Depends(converter.create)
    ) -> AccountData:
        user_data = self.users.find_user(
            {"email-hash": Encryption.sha256(email + "supahcool")}, True
        )
        if user_data is None:
            raise HTTPException(status_code=404, detail="User not found (find_item)")

        user_profile: AccountData | None = self.admin_tools.get_user_details_by_id(
            user_data["_id"]
        )

        if not user_profile:
            raise HTTPException(status_code=404, detail="User not found (get profile)")

        return user_profile

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_id(
        self, id: str, session: Session = Depends(converter.create)
    ) -> AccountData:
        user_data: AccountData | None = self.admin_tools.get_user_details_by_id(id)

        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")

        return user_data

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_username(
        self, username: str, session: Session = Depends(converter.create)
    ) -> AccountData:
        user_data: AccountData | None = self.admin_tools.find_by_username(username)

        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")

        return user_data

    @Session.requires_auth
    @Session.requires_permission(permission="dns")
    def delete_dns_record(
        self, record: str, type: str, session: Session = Depends(converter.create)
    ):
        if not self.admin_tools.dns.delete_domain(record, type):
            raise HTTPException(status_code=503, detail="Failed to delete record")

    @Session.requires_auth
    @Session.requires_permission(permission="manage-permissions")
    def change_permission(
        self,
        id: str,
        permission: str,
        value: bool | int | str,
        session: Session = Depends(converter.create),
    ) -> None:
        if not self.admin_tools.change_permission(id, permission, value):
            raise HTTPException(status_code=404, detail="User not found")

    @Session.requires_auth
    @Session.requires_permission(permission="manage-permissions")
    def add_tld(
        self,
        id: str,
        tld: str,
        session: Session = Depends(converter.create),
    ) -> None:
        if tld not in get_args(AVAILABLE_TLDS):
            raise HTTPException(status_code=412, detail=f"Invalid TLD {tld}")

        self.admin_tools.add_domain(id, tld)  # type: ignore

    @Session.requires_auth
    @Session.requires_permission(permission="manage-permissions")
    def remove_tld(
        self,
        id: str,
        tld: str,
        session: Session = Depends(converter.create),
    ) -> None:
        if tld not in get_args(AVAILABLE_TLDS):
            raise HTTPException(status_code=412, detail=f"Invalid TLD {tld}")

        self.admin_tools.remove_domain(id, tld)  # type: ignore

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def verify(
        self,
        id: str,
        session: Session = Depends(converter.create),
    ) -> None:
        self.admin_tools.verify(id)  # type: ignore

    @Session.requires_auth
    def can_access(self, session: Session = Depends(converter.create)):
        if "admin" not in session.permissions:
            raise HTTPException(status_code=403, detail="Invalid permission")
