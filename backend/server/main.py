import uvicorn
from fastapi import FastAPI, APIRouter
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from server.routes.user import User
from database.tables.general import General
from database.tables.sessions import Sessions
from database.tables.invitation import Invites
from database.tables.codes import Codes
from mail.email import Email



print(load_dotenv())



app = FastAPI()

client:MongoClient = MongoClient(os.getenv("MONGODB_URL"))

general:General = General(client)
session:Sessions = Sessions(client)
invites:Invites = Invites(client)
codes:Codes = Codes(client)

email:Email = Email(codes,general)

app.include_router(User(general,session,invites,email).router)


if __name__ == "__main__":
    uvicorn.run(app)