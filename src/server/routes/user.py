import os
from typing import List, Dict, Annotated, Any
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
from security.api import Api
from security.convert import Convert
from mail.email import Email    


from dns_.dns import DNS

from server.routes.models.user import SignUp, PasswordReset, ApiGetKeys

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
                200: {"description":"Settings retrieved"},
                460: {"description": "Invalid session"}
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
                404: {"description": "Account does not exist"},
                460: {"description": "Invalid session"}
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
                200: {"description":"Deletion email sent"},
                460: {"description": "Invalid session"}
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
            responses={
                404: {"description": "Session does not exist"},
                460: {"description": "Invalid session"},
                461: {"description":"User does not have access to use that session"}
            },
            status_code=200,
            tags=["account","session"]
        )
        
        self.router.add_api_route(
            "/gdpr",
            self.get_gdpr,
            methods=["GET"],
            responses={
                404: {"description": "Session does not exist"},
                460: {"description": "Invalid session"},
                461: {"description":"User does not have access to use that session"}
            },
            status_code=200,
            tags=["account","privacy"]
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
            tags=["account","api"]
        )
        
        self.router.add_api_route(
            "/api/get-keys",
            self.get_api_keys,
            methods=["GET"],
            responses={
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account","api"]
        )


        logger.info("Initialized")
    

    def login(self,request:Request, x_auth_request:Annotated[str, Header()]):
        login_token:List[str] = x_auth_request.split("|") 

        username_hash:str = login_token[0]
        password_hash:str = login_token[1]

        user_data: UserType | None = self.table.find_user({"_id":username_hash})

        if user_data is None:
            raise HTTPException(status_code=404,detail="User does not exist")
        
        if not user_data["verified"]:
            raise HTTPException(status_code=403, detail="Verification required")
        
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
        from_url: str = request.headers.get("Origin", "https://www.frii.site")
        
        try:
            user_id:str = self.table.create_user(
                body.username,
                body.password,
                body.email,
                body.language,
                country,
                round(time.time()),
                self.email,
                body.invite,
                from_url
            )
        except EmailException:
            raise HTTPException(status_code=422, detail="Email already in use")
        except UsernameException:
            raise HTTPException(status_code=409, detail="Username already in use")
        self.invites.use(user_id,body.invite)


    @Session.requires_auth
    def get_settings(self, session:Session = Depends(converter.create)) -> UserPageType:
        return JSONResponse(self.table.get_user_profile(session.username,self.session_table)) # type: ignore[return-value]
    

    def resend_verification(self, request:Request, user_id:str):
        self.codes.create_code("verification",user_id)
        from_url: str = request.headers.get("Origin", "https://www.frii.site")

        user_data:UserType | None = self.table.find_user({"_id":user_id})

        if user_data is None:
            logger.info(f"Could not find user with id {user_id}")
            raise HTTPException(status_code=404, detail="User not found")
        
        if user_data["verified"]:
            raise HTTPException(status_code=409, detail="Account already verified")
        
        email:str = self.encryption.decrypt(user_data["email"])

        self.email.send_verification_code(from_url, user_id,email)


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
        if request.headers.get("specific")  == "true":
            # The following will not be null if since if `specified` then id header must be present
            session_id_hash = request.headers.get("id") # type: ignore[assignment]
        else:
            session_id_hash = Encryption.sha256(session.id)
            
        try:
            session.delete(session_id_hash)
        except SessionError:
            raise HTTPException(404)
        except SessionPermissonError:
            raise HTTPException(461)
        
    @Session.requires_auth
    def create_api_token(self, request:Request, comment:str, permissions:List[str], session:Session = Depends(converter.create)) -> str:
        api_key:str
        try:
            api_key = Api.create(session.username,self.table,comment, permissions)
        except PermissionError:
            raise HTTPException(403)
        
        return api_key
    
            
    @Session.requires_auth
    def get_api_keys(self, request:Request, session:Session = Depends(converter.create)) -> List[ApiGetKeys]:
        
        api_keys = session.user_cache_data["api-keys"]
        user_keys: List[Dict] = []
        
        # convert old api key format into new one:
        def convert_keys(key: dict) -> Dict:
            updated_key = {
                "key": key["key"],
                "domains": key["domains"],
                "comment": key["comment"],
                "perms": []
            }
            
            
            has_migratable_perms: bool = any([item in ["content", "type", "domain", "view"] for item in key["perms"]])
            
            if not has_migratable_perms:
                raise ValueError("No keys to migrate!")
            
            logger.info("Migrating API key...")
            
            for perm in key["perms"]:
                if key in ["content", "type"] and "modify" not in updated_key["perms"]:
                    updated_key["perms"].append("content")
                elif key == "domain":
                    updated_key["perms"].append("register")
                elif key == "view":
                    updated_key["perms"].append("list")
                else:
                    logger.info("No migrateable keys found")
        
            return key
        
        for key in api_keys:
            decrypted_access_key:str = self.table.encryption.decrypt(api_keys[key]["string"])
            
            api_key = {"key":decrypted_access_key,
                 "domains":api_keys[key]["domains"], 
                 "perms":api_keys[key]["perms"],
                 "comment":api_keys[key]["comment"]
                }

            try:
                logger.info("API key needs to be migrated. Performing automatic migration")
                updated_key: Dict = convert_keys(api_key)
                self.table.modify_document(
                    {"_id": session.id},
                    "$set", f"api-keys.{key}.perms",
                    updated_key["perms"]
                )
                
                user_keys.append(updated_key)
                
            except ValueError:
                logger.info("API key is up to date.")
                user_keys.append(api_key)
            
            
        return user_keys # type: ignore[return-value]

    
    @Session.requires_auth
    def get_gdpr(self, request:Request, session:Session = Depends(converter.create)) -> Dict[Any,Any]:
        user_data: UserType = session.user_cache_data
        
        gdpr_keys:List[str] = ["_id", "lang", "country",
                     "created", "last-login",
                     "permissions", "verified",
                     "domains", "feature-flags",
                     "beta-enroll"]
    
        return {k:v for k,v in user_data if k in gdpr_keys} # type: ignore[has-type, misc]



    def verify_deletion(self, code:str):
        code_status:CodeStatus = self.codes.is_valid(code,"deletion")

        if not code_status["valid"]:
            raise HTTPException(status_code=400, detail="Code is not valid")
        
        user_id:str = self.encryption.decrypt(code_status["account"])
        user_data: UserType | None = self.table.find_user({"_id":user_id})

        if user_data is None:
            raise HTTPException(status_code=404, detail="Account not found")



        domains = {k: v["type"] for k, v in user_data["domains"].items()}
        
        success = self.dns.delete_multiple(domains)
        if not success:
            logger.error("Domain mass deletion failed! Continuing with account deletion.")
            
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
        