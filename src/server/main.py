from typing import List, Dict
import threading
import logging
import sys
import datetime
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from logtail import LogtailHandler # type: ignore[import-untyped]
from dotenv import load_dotenv
import json

from server.routes.user import User
from server.routes.invite import Invite
from server.routes.domain import Domain
from server.routes.blog import Blog
from server.routes.languages import Languages
from server.routes.api import API

from database.tables.users import Users
from database.tables.sessions import Sessions
from database.tables.invitation import Invites
from database.tables.codes import Codes
from database.tables.domains import Domains
from database.tables.blogs import Blogs
from database.tables.translations import Translations

from dns_.dns import DNS

from security.session import SessionError, SessionPermissonError
from security.encryption import Encryption
from security.api import ApiError, ApiRangeError, ApiPermissionError
from mail.email import Email

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(name)s] %(levelname)s: [%(filename)s:%(funcName)s] %(message)s",
    datefmt="%d/%m/%Y %H.%M.%S",
    stream=sys.stdout
)
betterStackHandler = LogtailHandler(
    source_token = os.getenv("BSTACK_SOURCE"),
    host = os.getenv("BSTACK_HOST")
)
logger:logging.Logger = logging.getLogger("frii.site")
logger.handlers = []
logger.addHandler(betterStackHandler)

logger.info("Logger init")

if not load_dotenv():
    logger.warning("Failed to load .env file")

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
    },
    {
        "name": "api",
        "description": "Routes that can be used with the public API"
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

class VariableInitializer:
    def __init__(self) -> None:
        pass
    
    def gather_users(self) -> None:
        self.users:Users = Users(client)
    def gather_sessions(self) -> None:
        self.sessions:Sessions = Sessions(client)
    def gather_invites(self) -> None:
        self.invites:Invites = Invites(client)
    def gather_codes(self) -> None:
        self.codes:Codes = Codes(client)
    def gather_domains(self) -> None:
        self.domains:Domains = Domains(client)
        self.dns:DNS = DNS(self.domains)
    def gather_blogs(self) -> None:
        self.blogs:Blogs = Blogs(client)
    def gather_translations(self) -> None:
        self.translations = Translations(client)
        

v = VariableInitializer()

threads: Dict[str,threading.Thread] = {
    "users":threading.Thread(target=v.gather_users),
    "sessions":threading.Thread(target=v.gather_sessions),
    "invites":threading.Thread(target=v.gather_invites),
    "codes":threading.Thread(target=v.gather_codes),
    "domains":threading.Thread(target=v.gather_domains),
    "blogs":threading.Thread(target=v.gather_blogs),
    "translations":threading.Thread(target=v.gather_translations)
}

for thread in threads.values():
    thread.start()
    

threads["users"].join()
threads["domains"].join()
app.include_router(API(v.users,v.domains,v.dns).router)

threads["sessions"].join()
app.include_router(Domain(v.users,v.sessions,v.domains,v.dns).router)

threads["invites"].join()
app.include_router(Invite(v.users,v.sessions, v.invites).router)

threads["blogs"].join()
app.include_router(Blog(v.blogs,v.users,v.sessions).router)

threads["codes"].join()
email:Email = Email(v.codes,v.users, Encryption(os.environ["ENC_KEY"]))
app.include_router(User(v.users,v.sessions,v.invites,email, v.codes, v.dns).router)

threads["translations"].join()
app.include_router(Languages(v.translations,v.users,v.sessions).router)


@app.get("/status")
async def status():
    return JSONResponse(
        status_code=200,
        content={
            "started-at": datetime.datetime.fromtimestamp(float(os.environ.get("started-at"))).isoformat(),
            "start-elapsed": f"{os.environ.get('start-elapsed')}s"
        }
    )

@app.exception_handler(SessionError)
async def session_except_handler(request:Request, e:Exception):
    return JSONResponse(
        status_code=460,
        content={
            "message": "Invalid session"
        }
    )
    
@app.exception_handler(SessionPermissonError)
async def session_permission_except_handler(request:Request, e:Exception):
    return JSONResponse(
        status_code=461,
        content={
            "message": "You lack the necessary permissions to run this action"
        }
    )

@app.exception_handler(ApiError)
async def api_except_handler(request:Request, e:Exception):
    return JSONResponse(
        status_code=460,
        content={
            "message": "Invalid API key"
        }
    )
    
@app.exception_handler(ApiRangeError)
async def api_range_except_handler(request:Request, e:Exception):
    return JSONResponse(
        status_code=461,
        content={
            "message": "API key cannot do operations on requested domain"
        }
    )
        
@app.exception_handler(ApiPermissionError)
async def api_permission_except_handler(request:Request, e:Exception):
    return JSONResponse(
        status_code=462,
        content={
            "message": "API key does not have the necessary permissions to perform this action"
        }
    )