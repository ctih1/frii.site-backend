import os
from typing import List, Dict, Annotated
import time
import logging
from fastapi import APIRouter, Request, Depends, Header
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
import ipinfo # type: ignore[import-untyped]

from database.exceptions import EmailException, UsernameException, FilterMatchError
from database.tables.users import Users, UserType, CountryType, UserPageType
from database.tables.invitation import Invites
from database.tables.sessions import Sessions
from database.tables.codes import Codes, CodeStatus
from database.tables.domains import DomainFormat

from security.encryption import Encryption
from security.session import Session, SessionCreateStatus, SessionError, SessionPermissonError, SESSION_TOKEN_LENGTH
from security.convert import Convert
from mail.email import Email    


from dns_.dns import DNS

from server.routes.models.user import SignUp, PasswordReset

converter:Convert = Convert()
logger:logging.Logger = logging.getLogger("frii.site")
class User:
    def __init__(self,table:Users, session_table: Sessions, invite_table:Invites, email:Email, codes:Codes, dns:DNS) -> None:
        converter.init_vars(table,session_table)

        self.table:Users = table
        self.session_table:Sessions = session_table
        self.invites:Invites = invite_table
        self.email:Email = email
        self.codes:Codes = codes
        self.dns:DNS = dns

        self.encryption:Encryption = Encryption(os.getenv("ENC_KEY")) # type: ignore[arg-type]

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
            },
            tags=["account","session"]
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
            status_code=200,
            tags=["account"]
        )
        

                        
        self.router.add_api_route(
            "/settings",
            self.get_settings,
            methods=["GET"],
            responses={
                200: {"description":"Sign up succesfull"}
            },
            status_code=200,
            tags=["account"]
        )

        
        self.router.add_api_route(
            "/email/send",
            self.resend_verification,
            methods=["POST"],
            responses={
                200: {"description": "Email sent succesfully"},
                404: {"description": "Account does not exist"}
            },
            status_code=200,
            tags=["account"]
        )
        

        self.router.add_api_route(
            "/email/verify",
            self.verify_account,
            methods=["POST"],
            responses={
                200: {"description": "Verified succesfully"},
                400: {"description": "Code is invalid"},
                404: {"description": "Account does not exist"}
            },
            status_code=200,
            tags=["account"]
        )

        self.router.add_api_route(
            "/deletion/send",
            self.send_account_deletion,
            methods=["DELETE"],
            responses={
                200: {"description":"Deletion email sent"}
            },
            status_code=200,
            tags=["account"]
        )

        
        self.router.add_api_route(
            "/deletion/verify",
            self.verify_deletion,
            methods=["DELETE"],
            responses={
                200: {"description": "Account deleted"},
                400: {"description": "Deletion code invalid"},
                404: {"description": "Account not found"}
            },
            status_code=200,
            tags=["account"]
        )

                
        self.router.add_api_route(
            "/recovery/send",
            self.send_recovery_link,
            methods=["POST"],
            responses={
                200: {"description": "Email sent"}
            },
            status_code=200,
            tags=["account"]
        )

        self.router.add_api_route(
            "/recovery/verify",
            self.reset_password,
            methods=["POST"],
            responses={
                200: {"description": "Email sent"},
                403: {"description": "Invalid code"},
                404: {"description": "User not found"}
            },
            status_code=200,
            tags=["account"]
        )

        self.router.add_api_route(
            "/logout",
            self.logout,
            methods=["PATCH"],
            status_code=200,
            tags=["account","session"]
        )

        logger.info("Initialized")
    

    def login(self,request:Request, x_auth_request:Annotated[str, Header()]):
        login_token:List[str] = x_auth_request.split("|") 

        username_hash:str = login_token[0]
        password_hash:str = login_token[1]

        user_data: UserType | None = self.table.find_user({"_id":username_hash})

        if user_data is None:
            raise HTTPException(status_code=404,detail="User does not exist")
        
        if not Encryption.check_password(password_hash,user_data["password"]):
            raise HTTPException(status_code=401, detail="Invalid password")
        
        session_status:SessionCreateStatus = Session.create(
            username_hash, 
            request.client.host, # type: ignore[union-attr]
            request.headers.get("User-Agent","Unknown"),
            self.table,
            self.session_table
        )

        if session_status["mfa_required"]:
            if not request.headers.get("X-MFA-Code"):
                raise HTTPException(status_code=412, detail="MFA required")
        
        if session_status["success"]:
            return JSONResponse({"auth-token":session_status["code"]})
        

    def sign_up(self, request:Request, body: SignUp) -> None:
        if not self.invites.is_valid(body.invite):
            raise HTTPException(status_code=400, detail="Invite not valid")
        
        country:CountryType = self.handler.getDetails(request.client.host).all # type: ignore[union-attr]

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
            raise HTTPException(status_code=422, detail="Email already in use")
        except UsernameException:
            raise HTTPException(status_code=409, detail="Username already in use")
        self.invites.use(user_id,body.invite)


    @Session.requires_auth
    def get_settings(self, session:Session = Depends(converter.create)) -> UserPageType:
        return JSONResponse(self.table.get_user_profile(session.username,self.session_table)) # type: ignore[return-value]
    

    def resend_verification(self, user_id:str):
        self.codes.create_code("verification",user_id)

        user_data:UserType | None = self.table.find_user({"_id":user_id})

        if user_data is None:
            raise HTTPException(status_code=404, detail="User not found")
        
        email:str = self.encryption.decrypt(user_data["email"])

        self.email.send_verification_code(user_id,email)


    def verify_account(self, code:str):
        code_status:CodeStatus = self.codes.is_valid(code,"verification")

        if not code_status["valid"]:
            raise HTTPException(status_code=400, detail="Code is not valid")
        
        try:
            self.table.modify_document(
                {"_id":self.encryption.decrypt(code_status["account"])},
                "$set",
                "verified",
                True
            )
        except FilterMatchError:
            raise HTTPException(status_code=404)
        
        self.codes.delete_code(code,"verification")


    @Session.requires_auth
    def send_account_deletion(self, request:Request, session:Session = Depends(converter.create)):
        email:str = self.encryption.decrypt(session.user_cache_data["email"])
        self.email.send_delete_code(session.username,email)

    @Session.requires_auth
    def logout(self, request:Request, session:Session = Depends(converter.create)) -> None:
        session_id_hash:str
        if request.query_params.get("specific")  == "true":
            session_id_hash = request.query_params.get("id")
        else:
            session_id_hash = Encryption.sha256(session.id)

        try:
            session.delete(session_id_hash)
        except SessionError:
            raise HTTPException(404)
        except SessionPermissonError:
            raise HTTPException(461)
        

    def verify_deletion(self, code:str):
        code_status:CodeStatus = self.codes.is_valid(code,"deletion")

        if not code_status["valid"]:
            raise HTTPException(status_code=400, detail="Code is not valid")
        
        user_id:str = self.encryption.decrypt(code_status["account"])
        user_data: UserType | None = self.table.find_user({"_id":user_id})

        if user_data is None:
            raise HTTPException(status_code=404, detail="Account not found")

        for key,value in user_data["domains"].items():
            key:str = key # type: ignore[no-redef]
            value:DomainFormat = value # type: ignore[no-redef]

            self.dns.delete_domain(value["id"])
            
        self.table.delete_document(
            {"_id":user_id}
        )

    def send_recovery_link(self, username:str): # username being a plaintext string 
        self.email.send_password_code(username)

    def reset_password(self, body: PasswordReset) -> None:
        code_status:CodeStatus = self.codes.is_valid(body.code,"recovery")

        if not code_status["valid"]:
            raise HTTPException(status_code=403, detail="Invalid code")
        
        password:str = self.encryption.create_password(body.hashed_password)
        username:str = code_status["account"]

        Session.clear_sessions(username,self.session_table)

        try:
            self.table.modify_document(
                {"_id":username},
                "$set",
                "password",
                password
                )
        except FilterMatchError:
            raise HTTPException(status_code=404,detail="Invalid user")
        