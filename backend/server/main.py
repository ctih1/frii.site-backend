import uvicorn
from fastapi import FastAPI, APIRouter, Request
from fastapi.responses import JSONResponse
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from server.routes.user import User
from server.routes.invite import Invite
from database.tables.general import General
from database.tables.sessions import Sessions
from database.tables.invitation import Invites
from database.tables.codes import Codes
from security.session import SessionError
from mail.email import Email



print(load_dotenv())



app = FastAPI()

client:MongoClient = MongoClient(os.getenv("MONGODB_URL"))

general:General = General(client)
sessions:Sessions = Sessions(client)
invites:Invites = Invites(client)
codes:Codes = Codes(client)

email:Email = Email(codes,general)

app.include_router(User(general,sessions,invites,email).router)
app.include_router(Invite(general,sessions, invites).router)

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