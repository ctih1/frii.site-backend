import os
from typing import List
import time
from fastapi import APIRouter, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
import ipinfo
from database.exceptions import EmailException, UsernameException
from database.table import Table
from database.tables.general import General, UserType, CountryType
from database.tables.invitation import Invites
from database.tables.sessions import Sessions
from security.encryption import Encryption
from security.session import Session, SessionCreateStatus, SESSION_TOKEN_LENGTH
from mail.email import Email
from server.routes.models.user import SignUp
class User:
    def __init__(self,table:General, session_table: Sessions, invite_table:Invites, email:Email) -> None:
        self.table:General = table
        self.session_table:Session = session_table
        self.invites:Invites = invite_table
        self.email:Email = email
        self.handler:ipinfo.Handler = ipinfo.getHandler(os.getenv("IPINFO_KEY"))
        
        self.router = APIRouter()
        
        self.router.add_api_route(
            "/login",
            self.login,
            methods=["POST"],
            responses={
                200: {"description":"Login succesfull", "content":{"application/json":{"code":f"String with the length of {SESSION_TOKEN_LENGTH}"}}},
                404: {"description": "User not found"},
                401: {"description": "Invalid password"},
                412: {"description": "2FA code required to be passed in X-MFA-Code"},
            }
        )
        
                
        self.router.add_api_route(
            "/sign-up",
            self.sign_up,
            methods=["POST"],
            responses={
                200: {"description":"Sign up succesfull"},
                400: {"description": "Invalid invite"},
                422: {"description": "Email is already in use"},
                409: {"description": "Username is already in use"},
            },
            status_code=200
        )
        
        

    def login(self,request:Request):
        login_token:List[str] = request.headers.get("X-Auth-Request").split("|")

        username_hash:str = login_token[0]
        password_hash:str = login_token[1]

        user_data: UserType | None = self.table.find_item({"_id":username_hash})

        if user_data is None:
            raise HTTPException(status_code=404,detail="User does not exist")
        
        if not Encryption.check_password(password_hash,user_data["password"]):
            raise HTTPException(status_code=401, detail="Invalid password")
        
        session_status:SessionCreateStatus = Session.create(
            username_hash,
            request.client.host,
            request.headers.get("User-Agent"),
            self.table,
            self.session_table
        )

        if session_status["mfa_required"]:
            if not request.headers.get("X-MFA-Code"): raise HTTPException(status=412, detail="MFA required")
        
        if session_status["success"]:
            return JSONResponse({"auth-token":session_status["code"]})
        
        
    def sign_up(self, request:Request, body: SignUp):
        if not self.invites.is_valid(body.invite):
            raise HTTPException(status_code=400, detail="Invite not valid")
        
        country:CountryType = self.handler.getDetails(request.client.host).all

        try:
            user_id:str = self.table.create_user(
                body.username,
                body.password,
                body.email,
                body.language,
                country,
                round(time.time()),
                self.email,
                body.invite
            )
        except EmailException:
            return HTTPException(status_code=422, detail="Email already in use")
        except UsernameException:
            return HTTPException(status_code=409, detail="Username already in use")
        self.invites.use(user_id,body.invite)
        
        

