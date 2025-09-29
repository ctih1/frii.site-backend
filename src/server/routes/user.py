import os
from typing import List, Dict, Annotated, Any
import time
import logging
import json
from fastapi import APIRouter, Request, Depends, Header, Query
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
import ipinfo  # type: ignore[import-untyped]

from database.exceptions import (
    ConflictingReferralCode,
    EmailException,
    UsernameException,
    FilterMatchError,
)
from database.tables.users import Users, UserType, CountryType, UserPageType
from database.tables.invitation import Invites
from database.tables.sessions import Sessions
from database.tables.codes import Codes, CodeStatus
from database.tables.domains import DomainFormat

from security.encryption import Encryption
from security.oauth import EmailError, OAuth, DuplicateAccount
from security.session import (
    Session,
    SessionCreateStatus,
    SessionError,
    SessionPermissonError,
    REFRESH_AMOUNT,
    ACCESS_AMOUNT,
)
from security.api import Api, ApiPermission, ApiType
from security.convert import Convert
from mail.email import Email
from security.captcha import Captcha

from dns_.dns import DNS

from server.routes.models.user import (
    ApiCreationBody,
    ApiDeletion,
    MFACreation,
    SignUp,
    PasswordReset,
    ApiGetKeys,
)

converter: Convert = Convert()
logger: logging.Logger = logging.getLogger("frii.site")


class User:
    def __init__(
        self,
        table: Users,
        session_table: Sessions,
        invite_table: Invites,
        email: Email,
        codes: Codes,
        dns: DNS,
    ) -> None:
        converter.init_vars(table, session_table)

        self.table: Users = table
        self.session_table: Sessions = session_table
        self.invites: Invites = invite_table
        self.email: Email = email
        self.codes: Codes = codes
        self.dns: DNS = dns
        self.captcha: Captcha = Captcha(os.getenv("TURNSTILE_KEY") or "")

        self.encryption: Encryption = Encryption(os.getenv("ENC_KEY"))  # type: ignore[arg-type]

        self.handler: ipinfo.Handler = ipinfo.getHandler(os.getenv("IPINFO_KEY"))

        self.router = APIRouter()

        self.router.add_api_route(
            "/settings",
            self.get_settings,
            methods=["GET"],
            responses={
                200: {"description": "Settings retrieved"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/email/send",
            self.resend_verification,
            methods=["POST"],
            responses={
                200: {"description": "Email sent succesfully"},
                404: {"description": "Account does not exist"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/email/verify",
            self.verify_account,
            methods=["POST"],
            responses={
                200: {"description": "Verified succesfully"},
                400: {"description": "Code is invalid"},
                404: {"description": "Account does not exist"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/deletion/send",
            self.send_account_deletion,
            methods=["DELETE"],
            responses={
                200: {"description": "Deletion email sent"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/deletion/verify",
            self.verify_deletion,
            methods=["DELETE"],
            responses={
                200: {"description": "Account deleted"},
                400: {"description": "Deletion code invalid"},
                404: {"description": "Account not found"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/recovery/send",
            self.send_recovery_link,
            methods=["POST"],
            responses={200: {"description": "Email sent"}},
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/recovery/verify",
            self.reset_password,
            methods=["POST"],
            responses={
                200: {"description": "Email sent"},
                403: {"description": "Invalid code"},
                404: {"description": "User not found"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/gdpr",
            self.get_gdpr,
            methods=["GET"],
            responses={
                200: {"description": "GDPR data sent"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "privacy"],
        )

        self.router.add_api_route(
            "/referral",
            self.create_referral,
            methods=["POST"],
            responses={
                200: {"description": "Created referral"},
                400: {"description": "Invalid code length"},
                409: {"description": "Referral code has already been created"},
                412: {"description": "User has already created a codee"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "referral"],
        )

        self.router.add_api_route(
            "/api/create-key",
            self.create_api_token,
            methods=["POST"],
            responses={
                403: {"description": "User does not own requested domains"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "api"],
        )

        self.router.add_api_route(
            "/api/get-keys",
            self.get_api_keys,
            methods=["GET"],
            responses={
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "api"],
        )

        self.router.add_api_route(
            "/api/get-key",
            self.get_key,
            methods=["GET"],
            responses={
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "api"],
        )

        self.router.add_api_route(
            "/api/delete-key",
            self.delete_api_key,
            methods=["DELETE"],
            responses={
                404: {"description": "Key does not exist"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "api"],
        )

        self.router.add_api_route(
            "/mfa/create",
            self.create_mfa,
            methods=["POST"],
            responses={
                409: {"description": "Code already exists"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "2fa"],
        )

        self.router.add_api_route(
            "/mfa/verify",
            self.verify_mfa_setup,
            methods=["POST"],
            responses={
                401: {"description": "Invalid code"},
                409: {"description": "Code already exists"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "2fa"],
        )

        self.router.add_api_route(
            "/mfa/delete",
            self.delete_mfa,
            methods=["DELETE"],
            responses={
                401: {"description": "Invalid code"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "2fa"],
        )
        self.router.add_api_route(
            "/mfa/recovery",
            self.delete_mfa_with_username_pass,
            methods=["DELETE"],
            responses={
                401: {"description": "Invalid password"},
                404: {"description": "Account doesnt exist"},
                409: {"description": "Invalid recovery code"},
                412: {"description": "MFA not enabled"},
            },
            status_code=200,
            tags=["account", "2fa"],
        )

        logger.info("Initialized")

    def create_mfa(
        self, request: Request, session: Session = Depends(converter.create)
    ) -> MFACreation:
        if session.user_cache_data.get("totp", {}).get("verified"):
            raise HTTPException(status_code=409, detail="MFA code already exists!")
        status = session.create_2fa()
        return {"app_link": status["url"], "backup_codes": status["codes"]}  # type: ignore[return-value]

    def verify_mfa_setup(
        self,
        request: Request,
        x_mfa_code: Annotated[str, Header()],
        session: Session = Depends(converter.create),
    ) -> None:
        if session.user_cache_data.get("totp", {}).get("verified"):
            raise HTTPException(status_code=409, detail="MFA code already exists!")
        if not session.verify_2fa(x_mfa_code):
            raise HTTPException(status_code=401, detail="Code is invalid")

    def delete_mfa(
        self,
        request: Request,
        session: Session = Depends(converter.create),
        x_mfa_code: Annotated[str | None, Header()] = None,
        x_backup_code: Annotated[str | None, Header()] = None,
    ):
        if not x_mfa_code and not x_backup_code:
            raise HTTPException(
                status_code=412,
                detail="X-MFA-Code or X-Backup-Code needs to be specified!",
            )

        try:
            session.remove_mfa(x_backup_code, x_mfa_code)
        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid code")

    def delete_mfa_with_username_pass(
        self,
        request: Request,
        x_auth_request: Annotated[str, Header()],
        x_backup_code: Annotated[str, Header()],
    ):
        # x_plain_username is used to mitigate a bug in the backend, causing none of the actual usernames just to be saved, just their hashes

        login_token: List[str] = x_auth_request.split("|")

        username_hash: str = login_token[0]
        password_hash: str = login_token[1]

        user_data: UserType | None = self.table.find_user({"_id": username_hash})

        if user_data is None:
            raise HTTPException(status_code=404, detail="User does not exist")

        if not user_data.get("totp", {}).get("verified"):
            raise HTTPException(412, detail="User does not have MFA")

        if user_data.get(
            "registered-with", "email"
        ) == "email" and not Encryption.check_password(
            password_hash, user_data["password"]  # type: ignore
        ):
            raise HTTPException(status_code=401, detail="Invalid password")

        try:
            Session.remove_mfa_static(
                username_hash, self.table, user_data, x_backup_code
            )
        except ValueError:
            raise HTTPException(status_code=409)

    @Session.requires_auth
    def get_settings(
        self, session: Session = Depends(converter.create)
    ) -> UserPageType:
        return JSONResponse(self.table.get_user_profile(session.username, self.session_table))  # type: ignore[return-value]

    def resend_verification(self, request: Request, user_id: str):
        self.codes.create_code("verification", user_id)
        from_url: str = request.headers.get("Origin", "https://www.frii.site")

        user_data: UserType | None = self.table.find_user({"_id": user_id})

        if user_data is None:
            logger.info(f"Could not find user with id {user_id}")
            raise HTTPException(status_code=404, detail="User not found")

        if user_data["verified"]:
            raise HTTPException(status_code=409, detail="Account already verified")

        email: str = self.encryption.decrypt(user_data["email"])

        self.email.send_verification_code(from_url, user_id, email)

    def verify_account(self, code: str):
        code_status: CodeStatus = self.codes.is_valid(code, "verification")

        if not code_status["valid"]:
            raise HTTPException(status_code=400, detail="Code is not valid")

        try:
            self.table.modify_document(
                {"_id": code_status.get("account", None)}, "$set", "verified", True
            )

            user: UserType | None = self.table.find_user(
                {"_id": code_status.get("account")}
            )
            if not user:
                raise FilterMatchError("User not found")

            referred_by: str | None = user.get("referred-by")

            if referred_by:
                logger.info("Using referral code")
                self.table.referrals.use(user, referred_by)

        except FilterMatchError:
            raise HTTPException(status_code=404)

        self.codes.delete_code(code, "verification")

    @Session.requires_auth
    def send_account_deletion(
        self,
        request: Request,
        x_mfa_code: Annotated[str, Header()],
        session: Session = Depends(converter.create),
    ):
        from_url: str = request.headers.get("Origin", "https://www.frii.site")
        if session.user_cache_data.get("totp", {}).get(
            "verified"
        ) and not session.check_code(x_mfa_code):
            raise HTTPException(status_code=412, detail="Invalid MFA code")

        email: str = self.encryption.decrypt(session.user_cache_data["email"])
        self.email.send_delete_code(from_url, session.username, email)

    @Session.requires_auth
    def create_api_token(
        self,
        request: Request,
        body: ApiCreationBody,
        session: Session = Depends(converter.create),
    ) -> str:
        api_key: str
        try:
            api_key = Api.create(
                session.username,
                self.table,
                body.comment,
                body.permissions,
                body.domains,
            )
        except PermissionError:
            raise HTTPException(403, detail="You need to own domains specified")

        return api_key

    @Session.requires_auth
    def get_api_keys(
        self, request: Request, session: Session = Depends(converter.create)
    ) -> Dict[str, ApiType]:
        api_keys = session.user_cache_data.get("api-keys", {})

        return api_keys

    @Session.requires_auth
    def get_key(
        self,
        hash: str,
        request: Request,
        session: Session = Depends(converter.create),
    ) -> str:
        api_keys = session.user_cache_data.get("api-keys", {})

        if api_keys.get(hash) is None:
            raise HTTPException(status_code=404, detail="Key does not exist!")

        if api_keys.get(hash, {}).get("string") is None:  # type: ignore [call-overload]
            raise HTTPException(status_code=412, detail="Wrong API key format!")

        return self.encryption.decrypt(api_keys.get(hash, {}).get("string", ""))  # type: ignore [call-overload]

    @Session.requires_auth
    def delete_api_key(
        self,
        body: ApiDeletion,
        request: Request,
        session: Session = Depends(converter.create),
    ) -> None:
        api_keys = session.user_cache_data.get("api-keys", {})

        if body.hash not in api_keys:
            raise HTTPException(status_code=404, detail="Key does not exist")

        self.table.remove_key(
            {"_id": session.user_cache_data["_id"]}, f"api-keys.{body.hash}"
        )

    @Session.requires_auth
    def get_gdpr(
        self, request: Request, session: Session = Depends(converter.create)
    ) -> Dict[Any, Any]:
        user_data: UserType = session.user_cache_data

        gdpr_keys: List[str] = [
            "_id",
            "lang",
            "country",
            "created",
            "last-login",
            "permissions",
            "verified",
            "domains",
            "feature-flags",
            "beta-enroll",
            "registered-with",
        ]

        return {k: v for k, v in user_data.items() if k in gdpr_keys}  # type: ignore[has-type, misc]

    @Session.requires_auth
    def create_referral(
        self, code: str, request: Request, session: Session = Depends(converter.create)
    ) -> None:
        if session.user_cache_data.get("referral-code"):
            raise HTTPException(
                status_code=412, detail="User already has referral code!"
            )

        try:
            self.table.referrals.create(session.user_id, code)
        except ConflictingReferralCode:
            raise HTTPException(status_code=409, detail="Referral code taken")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid code length")

    def verify_deletion(self, code: str):
        code_status: CodeStatus = self.codes.is_valid(code, "deletion")

        if not code_status["valid"]:
            raise HTTPException(status_code=400, detail="Code is not valid")

        user_id: str = code_status.get("account", "")
        user_data: UserType | None = self.table.find_user({"_id": user_id})

        if user_data is None:
            raise HTTPException(status_code=404, detail="Account not found")

        domains = {k: v["type"] for k, v in user_data["domains"].items()}

        success = self.dns.delete_multiple(domains)
        if not success:
            logger.error(
                "Domain mass deletion failed! Continuing with account deletion."
            )

        self.table.delete_document({"_id": user_id})

    def send_recovery_link(self, username: str):  # username being a plaintext string
        self.email.send_password_code(username)

    def reset_password(self, body: PasswordReset) -> None:
        code_status: CodeStatus = self.codes.is_valid(body.code, "recovery")

        if not code_status["valid"]:
            raise HTTPException(status_code=403, detail="Invalid code")

        password: str = self.encryption.create_password(body.hashed_password)
        username: str = code_status.get("account", "")

        Session.clear_sessions(username, self.session_table)

        try:
            self.table.modify_document({"_id": username}, "$set", "password", password)
        except FilterMatchError:
            raise HTTPException(status_code=404, detail="Invalid user")
