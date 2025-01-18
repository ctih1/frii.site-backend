from typing import List, Dict
import uvicorn
from fastapi import FastAPI, APIRouter, Request
from fastapi.responses import JSONResponse
from pymongo import MongoClient
import os
from dotenv import load_dotenv

from server.routes.user import User
from server.routes.invite import Invite
from server.routes.domain import Domain

from database.tables.general import General
from database.tables.sessions import Sessions
from database.tables.invitation import Invites
from database.tables.codes import Codes
from database.tables.domains import Domains

from dns_.dns import DNS

from security.session import SessionError
from mail.email import Email



print(load_dotenv())


tags_metadata:List[Dict[str,str]] = [
    {
        "name": "domains",
        "description": "Viewing, creating, and managing domains"
    },
    {
        "name": "account",
        "description": "Getting account data, changing settings, signing up, logging in"
    },
    {
        "name": "invite",
        "description": "Viewing, creating, and managing invites"
    }
]


app = FastAPI()

client:MongoClient = MongoClient(os.getenv("MONGODB_URL"))

general:General = General(client)
sessions:Sessions = Sessions(client)
invites:Invites = Invites(client)
codes:Codes = Codes(client)
domains:Domains = Domains(client)
dns:DNS = DNS(domains)

email:Email = Email(codes,general)

app.include_router(User(general,sessions,invites,email, codes, dns).router)
app.include_router(Invite(general,sessions, invites).router)
app.include_router(Domain(general,sessions,domains,dns).router)

@app.exception_handler(SessionError)
async def session_except_handler(request:Request, e:Exception):
    return JSONResponse(
        status_code=460,
        content={
            "message": "Invalid session"
        }
    )


if __name__ == "__main__":
    uvicorn.run(app)