from .Logger import Logger
from .Session import Session
from .Database import Database
from .Utils import CredentialError
import time

import os
from dotenv import load_dotenv
load_dotenv()


l = Logger("blog.py",os.getenv("DC_WEBHOOK"),os.getenv("DC_TRACE")) # type: ignore
class Blog:
    def __init__(self,db:Database):
        self.db = db
    def get(self,code:str) -> dict:
        l.trace(f"GETting blog {code}")

        data = self.db.blog_collection.find_one({"_id":code})
        if(type(data) is dict):
            return data
        else:
            l.info(f"Blog {code} was not found in database")
            raise KeyError(f"Blog {code} not foun in database!")

    @Session.requires_auth
    @Session.requires_permission("blog")
    def create(self,session:Session, title:str,body:str,url=None) -> dict:
        if(url is None):
            url=title.lower().replace(" ","")
        self.db.blog_collection.insert_one({
            "_id":url[:24],
            "date": round(time.time()),
            "title":title,
            "body":body
        })

    def get_list(self,articles:int, content_length:int=0) -> list:
        """Gets the n articles and returns them as either

        content_length = 0
            {url:string, created:unix_timestamp(int)}
        content_length = n
            {url:string, created:unix_timestamp(int), body:string[:n], title:string}
        NOTE:`articles` < 50
        """
        if(articles>50):
            l.warn(f"Tried to get more than 50 articles {articles}. Denying request")
            raise ValueError("Maximum allowed articles is 50")
        results = []
        cursor = self.db.blog_collection.find().sort({"date":-1}).limit(articles)
        for article in cursor:
            if(content_length!=0):
                l.info(f"content_length != 0 {content_length} - returning details")
                results.append({
                    "url":article["_id"],
                    "created": article["date"],
                    "body": article["body"][:content_length],
                    "title": article["title"]
                })
            else:
                l.info(f"content_length == 0 {content_length} - returning overview")
                results.append({"url":article["_id"], "created": article["date"]})
        return results
