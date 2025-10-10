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
from dotenv import load_dotenv
import sentry_sdk

from server.routes.user import User
from server.routes.invite import Invite
from server.routes.domain import Domain
from server.routes.blog import Blog
from server.routes.api import API
from server.routes.admin import Admin
from server.routes.auth import Auth
from server.routes.kofi import Kofi

from database.tables.users import Users
from database.tables.sessions import Sessions
from database.tables.invitation import Invites
from database.tables.codes import Codes
from database.tables.domains import Domains
from database.tables.blogs import Blogs
from database.tables.status import Status
from database.tables.reward_codes import Rewards

from dns_.dns import DNS

from security.session import SessionError, SessionPermissonError
from security.encryption import Encryption
from security.api import ApiError, ApiRangeError, ApiPermissionError
from security.admin import Admin as AdminTools
from mail.email import Email

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(name)s] %(levelname)s: [%(filename)s:%(funcName)s] %(message)s",
    datefmt="%d/%m/%Y %H.%M.%S",
    stream=sys.stdout,
)

logger: logging.Logger = logging.getLogger("frii.site")
logger.handlers = []

logger.info("Logger init")

if not load_dotenv():
    logger.warning("Failed to load .env file")

tags_metadata: List[Dict[str, str]] = [
    {"name": "domains", "description": "Viewing, creating, and managing domains"},
    {
        "name": "account",
        "description": "Getting account data, changing settings, signing up, logging in",
    },
    {"name": "invite", "description": "Viewing, creating, and managing invites"},
    {"name": "api", "description": "Routes that can be used with the public API"},
]

sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN"),
    environment=(
        "development" if os.environ.get("debug", "") == "True" else "production"
    ),
    send_default_pii=True,
)

app = FastAPI()
app.state.safe_domains = [
    "https://www.frii.site",
    "https://development.frii.site",
    "https://canary.frii.site",
    "https://red.frii.site",
    "https://legacy.frii.site",
    "https://frii-site-frontend.vercel.app",
    "http://localhost:5173",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=app.state.safe_domains,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client: MongoClient = MongoClient(os.getenv("MONGODB_URL"))


class VariableInitializer:
    def __init__(self) -> None:
        pass

    def gather_users(self) -> None:
        self.users: Users = Users(client)
        self.rewards = Rewards(client, self.users)

    def gather_sessions(self) -> None:
        self.sessions: Sessions = Sessions(client)

    def gather_invites(self) -> None:
        self.invites: Invites = Invites(client)

    def gather_codes(self) -> None:
        self.codes: Codes = Codes(client)

    def gather_domains(self) -> None:
        self.domains: Domains = Domains(client)
        self.dns: DNS = DNS(self.domains)

    def gather_blogs(self) -> None:
        self.blogs: Blogs = Blogs(client)

    def gather_status(self) -> None:
        self.status = Status(client)


v = VariableInitializer()

threads: Dict[str, threading.Thread] = {
    "users": threading.Thread(target=v.gather_users),
    "sessions": threading.Thread(target=v.gather_sessions),
    "invites": threading.Thread(target=v.gather_invites),
    "codes": threading.Thread(target=v.gather_codes),
    "domains": threading.Thread(target=v.gather_domains),
    "blogs": threading.Thread(target=v.gather_blogs),
    "status": threading.Thread(target=v.gather_status),
}

for thread in threads.values():
    thread.start()


threads["users"].join()
threads["domains"].join()
app.include_router(API(v.users, v.domains, v.dns).router)


threads["sessions"].join()
app.include_router(Domain(v.users, v.sessions, v.domains, v.dns).router)

threads["invites"].join()
app.include_router(Invite(v.users, v.sessions, v.invites).router)

threads["blogs"].join()
app.include_router(Blog(v.blogs, v.users, v.sessions).router)

threads["codes"].join()

email: Email = Email(v.codes, v.users, Encryption(os.environ["ENC_KEY"]))
app.include_router(
    User(v.users, v.sessions, v.invites, email, v.codes, v.dns, v.rewards).router
)
app.include_router(Auth(v.users, v.sessions, v.invites, email, v.codes, v.dns).router)
app.include_router(Kofi(email, v.rewards).router)

app.include_router(
    Admin(
        v.users, v.sessions, AdminTools(v.users, v.sessions, v.domains, v.dns, email)
    ).router
)


@app.get("/status")
async def status():
    if not v.status:
        threads["status"].join()

    content = {
        "started-at": datetime.datetime.fromtimestamp(
            float(os.environ.get("started-at", "0"))
        ).isoformat(),
        "start-elapsed": f"{os.environ.get('start-elapsed')}s",
    }
    status = v.status.get()
    if status != None:
        content["message"] = status["message"]

    return JSONResponse(status_code=200, content=content)


@app.exception_handler(SessionError)
async def session_except_handler(request: Request, e: Exception):
    logger.warning(e.args)
    return JSONResponse(status_code=460, content={"message": "Invalid session"})


@app.exception_handler(SessionPermissonError)
async def session_permission_except_handler(request: Request, e: Exception):
    return JSONResponse(
        status_code=461,
        content={"message": "You lack the necessary permissions to run this action"},
    )


@app.exception_handler(ApiError)
async def api_except_handler(request: Request, e: Exception):
    return JSONResponse(
        status_code=460, content={"message": "Invalid API key", "detail": e.args}
    )


@app.exception_handler(ApiRangeError)
async def api_range_except_handler(request: Request, e: Exception):
    return JSONResponse(
        status_code=461,
        content={
            "message": "API key cannot do operations on requested domain",
            "detail": e.args,
        },
    )


@app.exception_handler(ApiPermissionError)
async def api_permission_except_handler(request: Request, e: Exception):
    return JSONResponse(
        status_code=462,
        content={
            "message": "API key does not have the necessary permissions to perform this action",
            "detail": e.args,
        },
    )


@app.exception_handler(KeyError)
async def key_error_handler(request: Request, e: Exception):
    logger.error(e)
    logger.error(e.__traceback__)
    return JSONResponse(
        status_code=500,
        content={"message": "KeyError"},
    )
