from typing import List, Annotated
import time
from fastapi import APIRouter, Request, Header, Depends
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from server.routes.models.invite import InviteCreate
from database.table import Table
from database.tables.general import General as GeneralTable, UserType
from database.tables.invitation import Invites as InviteTable
from database.tables.sessions import Sessions as SessionTable
from database.exceptions import (UserNotExistError, InviteException)
from security.encryption import Encryption
from security.session import Session, SessionCreateStatus, SESSION_TOKEN_LENGTH
from security.convert import Convert
from mail.email import Email

converter:Convert = Convert()

class Invite:
    def __init__(self, table:GeneralTable, sessions:SessionTable, invites:InviteTable) -> None:
        converter.init_vars(table,sessions)
        self.table:GeneralTable = table
        self.invites:InviteTable = invites

        self.router = APIRouter(prefix="/invite")

        self.router.add_api_route(
            "/create",
            self.create, 
            methods=["POST"],
            responses={
                200: {"description": "Invite code created"},
                409: {"description": "Invite limit (3) reached"}
            }
        )

    @Session.requires_auth
    @Session.requires_permission(permission="invite")
    def create(self,session:Session = Depends(converter.create)) -> InviteCreate:
        try:
            code:str = self.invites.create(session.username)
        except InviteException:
            return HTTPException(status_code=409)
        
        return {"code":code}


        
        
        
        
        
 
