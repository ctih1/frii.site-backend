import uvicorn
from fastapi import FastAPI, APIRouter
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from server.routes.user import User
from database.tables.general import General
from database.tables.sessions import Sessions

load_dotenv()

app = FastAPI()

client:MongoClient = MongoClient(os.getenv("MONGODB_URL"))

general:General = General(client)
session:Sessions = Sessions(client)

app.include_router(User(general,session).router)


if __name__ == "__main__":
    uvicorn.run(app)