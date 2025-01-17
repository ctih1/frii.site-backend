from typing import List
from fastapi import APIRouter, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from database.table import Table
from database.tables.general import General, UserType
from database.tables.sessions import Sessions
from security.encryption import Encryption
from security.session import Session, SessionCreateStatus, SESSION_TOKEN_LENGTH

class User:
    def __init__(self,table:General, session_table: Sessions) -> None:
        self.table:General = table
        self.session_table:Session = session_table
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
        
        

