from typing import List, Dict
import logging
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
import os
from dotenv import load_dotenv

from server.routes.user import User
from server.routes.invite import Invite
from server.routes.domain import Domain
from server.routes.blog import Blog

from database.tables.users import Users
from database.tables.sessions import Sessions
from database.tables.invitation import Invites
from database.tables.codes import Codes
from database.tables.domains import Domains
from database.tables.blogs import Blogs

from debug.status import Status

from dns_.dns import DNS

from security.session import SessionError
from mail.email import Email

logging.basicConfig(
    level=logging.INFO,
    format="[%(name)s] %(levelname)s: [%(filename)s:%(funcName)s] %(message)s",
    datefmt="%d/%m/%Y %H.%M.%S"
)
logger:logging.Logger = logging.getLogger("frii.site")
logger.info("Logger init")

logger.info(f".env loaded succesfully? {load_dotenv()}")


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client:MongoClient = MongoClient(os.getenv("MONGODB_URL"))

users:Users = Users(client)
sessions:Sessions = Sessions(client)
invites:Invites = Invites(client)
codes:Codes = Codes(client)
domains:Domains = Domains(client)
blogs:Blogs = Blogs(client)
dns:DNS = DNS(domains)
status:Status = Status(client)

email:Email = Email(codes,users)

app.include_router(User(users,sessions,invites,email, codes, dns).router)
app.include_router(Invite(users,sessions, invites).router)
app.include_router(Domain(users,sessions,domains,dns).router)
app.include_router(Blog(blogs,users,sessions).router)

@app.route("/status",["GET"])
async def get_status():
    if not status.get()["issues"]:
        return 200
    raise HTTPException(
        status_code=500,
        detail=f"{status.get()['message']}"
    )

@app.exception_handler(SessionError)
async def session_except_handler(request:Request, e:Exception):
    return JSONResponse(
        status_code=460,
        content={
            "message": "Invalid session"
        }
    )
