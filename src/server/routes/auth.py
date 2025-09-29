import os
from typing import List, Dict, Annotated, Any
import time
import logging
import json
from fastapi import APIRouter, Request, Depends, Header, Query
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
import ipinfo  # type: ignore[import-untyped]

from database.exceptions import EmailException, UsernameException
from database.tables.users import Users, UserType
from database.tables.invitation import Invites
from database.tables.sessions import Sessions
from database.tables.codes import Codes

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
from security.convert import Convert
from mail.email import Email
from security.captcha import Captcha

from dns_.dns import DNS

from server.routes.models.user import (
    SignUp,
)

converter: Convert = Convert()
logger: logging.Logger = logging.getLogger("frii.site")


class Auth:
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
            "/login",
            self.login,
            methods=["POST"],
            responses={
                200: {
                    "description": "Login succesfull",
                    "content": {
                        "application/json": {
                            "auth-token": f"Token you can use for accessing things",
                            "refresh-token": "Refreshing your auth-token after it expires in 15 minutes",
                        }
                    },
                },
                400: {"description": "User signed up with Google"},
                404: {"description": "User not found"},
                401: {"description": "Invalid password"},
                412: {"description": "2FA code required to be passed in X-MFA-Code"},
                429: {"description": "Invalid captcha"},
            },
            tags=["account", "session"],
        )

        self.router.add_api_route(
            "/refresh",
            self.refresh,
            methods=["POST"],
            responses={
                200: {
                    "description": "Refreshed tokens succesfully",
                    "content": {
                        "application/json": {
                            "auth-token": f"Token you can use for accessing things",
                            "refresh-token": "Refreshing your auth-token after it expires in 15 minutes",
                        }
                    },
                },
                460: {"description": "Invalid key"},
            },
            tags=["account", "session"],
        )

        self.router.add_api_route(
            "/auth/google/callback", self.google_oauth2, methods=["GET", "POST"]
        )
        self.router.add_api_route(
            "/auth/link", self.create_linking_code, methods=["POST"]
        )

        self.router.add_api_route(
            "/sign-up",
            self.sign_up,
            methods=["POST"],
            responses={
                200: {"description": "Sign up succesfull"},
                422: {"description": "Email is already in use"},
                409: {"description": "Username is already in use"},
                429: {"description": "Invalid captcha"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/logout",
            self.logout,
            methods=["PATCH"],
            responses={
                404: {"description": "Session does not exist"},
                460: {"description": "Invalid session"},
                461: {"description": "User does not have access to use that session"},
            },
            status_code=200,
            tags=["account", "session"],
        )

        logger.info("Initialized")

    def login(
        self,
        request: Request,
        x_auth_request: Annotated[str, Header()],
        x_captcha_code: Annotated[str, Header()],
        x_mfa_code: Annotated[str | None, Header()] = None,
        x_plain_username: Annotated[str | None, Header()] = None,
    ):
        # x_plain_username is used to mitigate a bug in the backend, causing none of the actual usernames just to be saved, just their hashes

        if not self.captcha.verify(x_captcha_code, request.client.host):  # type: ignore[union-attr]
            raise HTTPException(429, detail="Invalid captcha")

        login_token: List[str] = x_auth_request.split("|")

        username_hash: str = login_token[0]
        password_hash: str = login_token[1]

        if Encryption.sha256(x_plain_username or "") != username_hash:
            logger.warning("Plain username doesnt match login... Setting as none")
            x_plain_username = None

        user_data: UserType | None = self.table.find_user({"_id": username_hash})

        if user_data is None:
            raise HTTPException(status_code=404, detail="User does not exist")

        if not user_data["verified"]:
            raise HTTPException(status_code=403, detail="Verification required")

        if (
            user_data.get("password") is None
            or user_data.get("registered-with") == "google"
        ):
            raise HTTPException(status_code=400, detail="Account made with google")

        if not Encryption.check_password(password_hash, user_data["password"]):  # type: ignore
            raise HTTPException(status_code=401, detail="Invalid password")

        logger.info(f"Login attempt from {username_hash}")

        session_status: SessionCreateStatus = Session.create(
            username_hash,
            x_plain_username,
            x_mfa_code,
            request.client.host,  # type: ignore[union-attr]
            request.headers.get("User-Agent", "Unknown"),
            self.table,
            self.session_table,
        )

        if session_status["mfa_required"]:
            logger.debug(f"MFA error")
            raise HTTPException(status_code=412, detail="MFA required")

        if session_status["success"]:
            resp = JSONResponse({"auth-token": session_status["access_token"]})

            is_debug = os.environ.get("debug", "False") == "True"

            resp.set_cookie(
                "refresh-token",
                session_status["refresh_token"] or "invalid code",
                max_age=REFRESH_AMOUNT,
                path="/refresh",
                httponly=True,
                samesite="lax" if is_debug else "none",
                secure=False if is_debug else True,
            )

            return resp

    def refresh(self, request: Request):
        refresh_token: str | None = request.cookies.get("refresh-token")

        if not refresh_token:
            raise HTTPException(status_code=412, detail="refresh-token cookie missing")

        client = request.client
        if not client:
            raise HTTPException(status_code=500, detail="Invalid client?")

        session_data = Session.refresh(
            refresh_token,
            self.session_table,
            request.headers.get("User-Agent", ""),
            client.host,  # type: ignore[attr-defined]
        )

        if not session_data:
            raise HTTPException(status_code=465, detail="Failed to refresh token")

        access_token, refresh_token = session_data
        resp = JSONResponse({"auth-token": access_token})

        is_debug = os.environ.get("debug", "False") == "True"

        resp.set_cookie(
            "refresh-token",
            refresh_token,
            path="/refresh",
            httponly=True,
            max_age=REFRESH_AMOUNT,
            samesite="lax" if is_debug else "none",
            secure=False if is_debug else True,
        )

        return resp

    @Session.requires_auth
    def create_linking_code(self, session: Session = Depends(converter.create)) -> dict:
        code = self.codes.create_code("link", session.token)
        return {"code": code}

    def google_oauth2(self, request: Request, code: str = Query()) -> RedirectResponse:
        access = refresh = ""
        state: dict = json.loads(request.query_params.get("state", "{}"))
        origin = state.get("url", "https://www.frii.site")
        mode = state.get("mode", "login")
        redirect_url = state.get(
            "redirect", "https://api.frii.site/auth/google/callback"
        )

        logger.info(f"Request {mode} coming from origin {origin}")

        oauth = OAuth(self.table, self.session_table, self.email)

        if origin not in request.app.state.safe_domains:
            raise HTTPException(status_code=403, detail=f"Invalid origin {origin}")

        if mode == "login":
            try:
                access, refresh = oauth.create_google_session(
                    request, self.handler, code, redirect_url, state.get("referrer")
                )
            except ValueError:
                return RedirectResponse(f"{origin}/login?c=500&r=/")
            except DuplicateAccount:
                return RedirectResponse(f"{origin}/login?c=469&r=/")

            resp = RedirectResponse(f"{origin}/account/manage")

            is_debug = os.environ.get("debug", "False") == "True"

            resp.set_cookie(
                "auth-token",
                access,
                max_age=ACCESS_AMOUNT,
                samesite="lax" if is_debug else "none",
                secure=False if is_debug else True,
            )
            resp.set_cookie(
                "refresh-token",
                refresh,
                max_age=REFRESH_AMOUNT,
                path="/refresh",
                httponly=True,
                samesite="lax" if is_debug else "none",
                secure=False if is_debug else True,
            )

            return resp
        elif mode == "link":
            status = self.codes.is_valid(state.get("linking-code", ""), "link")
            if not status["valid"]:
                logger.info(f"Invalid linking code! {state.get('linking-code')}")
                raise SessionError("Invalid session!")

            session: Session = Session(
                status.get("account", ""), self.table, self.session_table
            )
            if not session.valid:
                logger.info("Linking code's session was invalid!")
                raise SessionError("Invalid session!")

            resp = RedirectResponse(f"{origin}/account/manage")

            try:
                oauth.link_google_account(session, request, code, redirect_url)
            except EmailError:
                resp = RedirectResponse(f"{origin}/login?c=472")
            except ValueError:
                resp = RedirectResponse(f"{origin}/login?c=409")

            return resp

        raise HTTPException(status_code=412, detail=f"Invalid mode {mode}")

    def sign_up(
        self, request: Request, body: SignUp, x_captcha_code: Annotated[str, Header()]
    ) -> None:
        if not self.captcha.verify(x_captcha_code, request.client.host):  # type: ignore[union-attr]
            raise HTTPException(429, detail="Invalid captcha")

        country = self.handler.getDetails(request.client.host).all  # type: ignore[union-attr]
        from_url: str = request.headers.get("Origin", "https://www.frii.site")

        refer = request.headers.get("x-refer-code")
        if refer:
            logger.info(f"Using refer {refer}")
        try:
            user_id: str = self.table.create_user(
                body.username,
                body.password,
                body.email,
                body.language,
                country,
                round(time.time()),
                self.email,
                from_url,
                refer_code=refer,
            )
        except EmailException:
            raise HTTPException(status_code=422, detail="Email already in use")
        except UsernameException:
            raise HTTPException(status_code=409, detail="Username already in use")

    @Session.requires_auth
    def logout(
        self, request: Request, session: Session = Depends(converter.create)
    ) -> None:
        session_id: str
        if request.headers.get("specific") == "true":
            # The following will not be null if since if `specified` then id header must be present
            session_id = request.headers.get("id")  # type: ignore[assignment]
        else:
            session_id = session.data.get("jti", "")

        try:
            session.delete(session_id)
        except SessionError:
            raise HTTPException(404)
        except SessionPermissonError:
            raise HTTPException(461)
