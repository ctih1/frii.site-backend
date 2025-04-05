from typing import List, Dict
import threading
import logging
import sys
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from dotenv import load_dotenv

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

from debug.status import Status

from dns_.dns import DNS

from security.session import SessionError, SessionPermissonError
from security.api import ApiError, ApiRangeError, ApiPermissionError
from mail.email import Email

logging.basicConfig(
    level=logging.INFO,
    format="%(thread)d - [%(name)s] %(levelname)s: [%(filename)s:%(funcName)s] %(message)s",
    datefmt="%d/%m/%Y %H.%M.%S",
    stream=sys.stdout
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
    def __init__(self):
        pass
    
    def gather_users(self):
        self.users:Users = Users(client)
    def gather_sessions(self):
        self.sessions:Sessions = Sessions(client)
    def gather_invites(self):
        self.invites:Invites = Invites(client)
    def gather_codes(self):
        self.codes:Codes = Codes(client)
    def gather_domains(self):
        self.domains:Domains = Domains(client)
        self.dns:DNS = DNS(self.domains)
    def gather_blogs(self):
        self.blogs:Blogs = Blogs(client)
    def gather_translations(self):
        self.translations = Translations(client)
        

v = VariableInitializer()

threads: List[threading.Thread] = [
    threading.Thread(target=v.gather_users),
    threading.Thread(target=v.gather_sessions),
    threading.Thread(target=v.gather_invites),
    threading.Thread(target=v.gather_codes),
    threading.Thread(target=v.gather_domains),
    threading.Thread(target=v.gather_blogs),
    threading.Thread(target=v.gather_translations)
]

for thread in threads:
    thread.start()
    thread.join()
    
    
email:Email = Email(v.codes,v.users)



app.include_router(User(v.users,v.sessions,v.invites,email, v.codes, v.dns).router)
app.include_router(Invite(v.users,v.sessions, v.invites).router)
app.include_router(Domain(v.users,v.sessions,v.domains,v.dns).router)
app.include_router(Blog(v.blogs,v.users,v.sessions).router)
app.include_router(Languages(v.translations,v.users,v.sessions).router)
app.include_router(API(v.users,v.domains,v.dns).router)

@app.get("/status")
async def status():
    return 200

@app.exception_handler(SessionError)
async def session_except_handler(request:Request, e:Exception):
    return JSONResponse(
        status_code=460,
        content={
            "message": "Invalid session"
        }
    )
    
@app.exception_handler(SessionPermissonError)
async def session_except_handler(request:Request, e:Exception):
    return JSONResponse(
        status_code=461,
        content={
            "message": "You lack the necessary permissions to run this action"
        }
    )

@app.exception_handler(ApiError)
async def session_except_handler(request:Request, e:Exception):
    return JSONResponse(
        status_code=460,
        content={
            "message": "Invalid API key"
        }
    )
    
@app.exception_handler(ApiRangeError)
async def session_except_handler(request:Request, e:Exception):
    return JSONResponse(
        status_code=461,
        content={
            "message": "API key cannot do operations on requested domain"
        }
    )
        
@app.exception_handler(ApiPermissionError)
async def session_except_handler(request:Request, e:Exception):
    return JSONResponse(
        status_code=462,
        content={
            "message": "API key does not have the necessary permissions to perform this action"
        }
    )