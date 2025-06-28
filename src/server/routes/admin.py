from typing import List, Annotated
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
        self, domain: str, userid: str, session: Session = Depends(converter.create)
    ):
        self.admin_tools.domains.delete_domain(userid, domain)

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_domain(
        self, domain: str, session: Session = Depends(converter.create)
    ) -> AccountData:
        user_profile: UserPageType | None = self.admin_tools.find_user_by_domain(domain)
        if user_profile is None:
            raise HTTPException(status_code=404, detail="User not found")

        user_data = self.users.find_user({f"domains.{domain}": {"$exists": True}}, True)
        if user_data is None:
            raise HTTPException(status_code=404, detail="User not found (find_item)")

        account_data: AccountData = user_profile  # type: ignore[assignment]
        account_data["domains"] = user_data["domains"]
        account_data["id"] = user_data["_id"]
        account_data["banned"] = user_data.get("banned", False)
        account_data["ban_reasons"] = user_data.get("ban-reasons", [])
        account_data["last_login"] = user_data.get("last-login", 0)

        return account_data

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

        user_profile: UserPageType | None = self.users.get_user_profile(
            user_data["_id"], self.sessions, find_banned=True
        )

        if user_profile is None:
            raise HTTPException(status_code=404, detail="User not found")

        account_data: AccountData = user_profile  # type: ignore[assignment]
        account_data["domains"] = user_data["domains"]
        account_data["id"] = user_data["_id"]
        account_data["banned"] = user_data.get("banned", False)
        account_data["ban_reasons"] = user_data.get("ban-reasons", [])
        account_data["last_login"] = user_data.get("last-login", 0)

        return account_data

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_id(
        self, id: str, session: Session = Depends(converter.create)
    ) -> AccountData:
        try:
            user_profile: UserPageType = self.users.get_user_profile(
                id, self.sessions, find_banned=True
            )
            user_data = self.users.find_user({"_id": id}, True)
            if user_data is None:
                raise HTTPException(
                    status_code=404, detail="User not found (find_item)"
                )

            account_data: AccountData = user_profile  # type: ignore[assignment]
            account_data["domains"] = user_data["domains"]
            account_data["id"] = user_data["_id"]
            account_data["banned"] = user_data.get("banned", False)
            account_data["ban_reasons"] = user_data.get("ban-reasons", [])
            account_data["last_login"] = user_data.get("last-login", 0)

            return account_data

        except UserNotExistError:
            raise HTTPException(status_code=404, detail="User not found")

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
    def can_access(self, session: Session = Depends(converter.create)):
        if "admin" not in session.permissions:
            raise HTTPException(status_code=403, detail="Invalid permission")
