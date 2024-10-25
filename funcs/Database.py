import time
from hashlib import sha256
from typing import TYPE_CHECKING
import bcrypt
from cryptography.fernet import Fernet
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.cursor import Cursor
from pymongo.database import Database as _Database

# pylint: disable=relative-beyond-top-level
from .Email import Email
from .Session import Session
from .Logger import Logger
import os
from dotenv import load_dotenv
load_dotenv()

l = Logger("Database.py",os.getenv("DC_WEBHOOK"),os.getenv("DC_TRACE")) # type: ignore

if TYPE_CHECKING:
    from Domain import Domain
    from Email import Email

class Database:
    def __init__(self,url:str,encryption_key:str):
        self.cluster: MongoClient = MongoClient(url)
        self.db: _Database = self.cluster["database"]
        self.collection: Collection = self.db["frii.site"]
        self.vuln_collection: Collection = self.db["vulnerabilities"]
        self.translation_collection: Collection = self.db["translations"]
        self.status_collection: Collection = self.db["status"]
        self.blog_collection:Collection = self.db["blog"]
        self.session_collection:Collection = self.db["sessions"]
        self.codes: Collection = self.db["codes"]
        self.api_collection:Collection = self.db["api"]
        self.verif_codes:dict={}
        self.encryption_key=encryption_key
        self.fernet = Fernet(bytes(encryption_key,"utf-8"))
        self.data_cache:dict={}
        self.status_data = None

    @l.time
    def check_database_for_domain(self,domain:str) -> bool:
        cursor:Cursor
        results_found:int=0
        cursor = self.collection.find({f"domains.{domain}":{"$exists":True}})
        for _ in cursor:
            results_found+=1
        return results_found!=0

    @l.time
    def __save_data(self,data: dict) -> None:
        """
        Saves data to mongodb
        """
        assert(type(data) is dict)
        self.collection.insert_one(data)


    @l.time
    def update_data(self,username: str, key: str, value: any) -> None:
        self.collection.update_one(
            {"_id": username},
            {"$set":{key:value},},
            upsert=False
        )
        self.remove_from_cache(username)

    @l.time
    @Session.requires_auth
    def __delete_user_from_db(self,session:Session) -> bool:
        self.remove_from_cache(session.username)
        self.collection.delete_one({"_id":session.username})
        return True

    @l.time
    @Session.requires_auth
    def add_domain(self,session: Session, domain_name:str, domain:dict) -> bool:
        l.info(f"Adding domain {domain_name} to user")
        self.remove_from_cache(session.username)
        self.collection.update_one({"_id":session.username},{"$set":{f"domains.{domain_name}":domain}})
        return True

    @l.time
    @Session.requires_auth
    def modify_domain(self,session:Session,domain: str, domain_data:dict) -> bool:
        domain = domain.replace(".","[dot]")
        l.info(f"Modifying domain {domain}")
        assert(domain!=None)
        self.remove_from_cache(session.username)
        self.collection.update_one({"_id":session.username},{"$set":{f"domains.{domain}":domain_data}})
        return True

    @l.time
    @Session.requires_auth
    def get_data(self,session:Session) -> dict:
        if(self.__get_cache(session) is not None):
            l.trace(f"Found user {session.username} in cache")
            return self.__get_cache(session)
        cursor: Cursor
        results_found: list = []
        cursor = self.collection.find({"_id":session.username})
        for result in cursor:
            results_found.append(result)
        self.__add_to_cache(results_found[0],session.username)
        if(results_found.__len__()!=0):
            return results_found[0]
        else:
            l.warn(f"`get_data` no matches for username {session.username}")
            raise IndexError("No matches for username.")

    @l.time
    def __user_exists(self,username: str) -> bool:
        cursor:Cursor
        results:int=0
        cursor = self.collection.find({"_id":username})
        for _ in cursor:
            results+=1
        return results!=0

    @l.time
    def __email_taken(self,email:str) -> bool:
        p_email = email.replace("+","@")
        p_email = p_email.split("@")
        p_email = f"{p_email[0]}@{p_email[-1]}" # to avoid duplicate domains (test@tld, test+5@tld...)
        email_hash = str(sha256((p_email+"supahcool").encode("utf-8")).hexdigest())
        l.info(f"Checking if email {email_hash} is in use")
        cursor:Cursor
        results:int=0
        cursor = self.collection.find({"email-hash":email_hash})
        for _ in cursor:
            results +=1
        return results != 0

    @Session.requires_auth
    @Session.requires_permission(perm="userdetails")
    def admin_get_basic_data(self,session:Session,id:str) -> dict:
        raw_data:dict = self.collection.find_one(id)
        return {
            "Error":False,
            "username": (self.fernet.decrypt(str.encode(raw_data["display-name"]))).decode("utf-8"),
            "email": (self.fernet.decrypt(str.encode(raw_data["email"]))).decode("utf-8"),
            "created": raw_data["created"],
            "last-login": raw_data["last-login"],
            "domains": raw_data.get("domain"),
            "permissions": raw_data.get("permissions")
        }

    @Session.requires_auth
    @Session.requires_permission(perm="userdetails")
    def admin_get_emails(self,session:Session,condition:dict) -> dict:
        results = self.collection.find(condition)
        emails:list=[]
        for result in results:
            emails.append(self.fernet.decrypt(str.encode(result["email"])).decode("utf-8"))
        return {"Error":False,"emails":emails}

    @l.time
    def create_user(self,username: str, password: str, email: str, language: str, country, time_signed_up, emailInstance:'Email') -> dict:
        """Creates a new user

        Args:
            username (str): Username of new user
            password (str): Password of new user
            email (str): email of the new user
            language (str): users language in the brwser
            country (str): users country
            time_signed_up (_type_): current tmie
            emailInstance (Email): instance of Email to send verfication

        Returns:
            error:
                `{"Error":True,"code":...,"message":...}`
            success:
                `{"Error":False}`
            codes:
                1001 - User exists
                1002 - email in use
                1003 - Invalid email
        """
        original_username=username
        username = str(sha256(username.encode("utf-8")).hexdigest())
        password: str = str(sha256(password.encode("utf-8")).hexdigest())
        if self.__user_exists(username):
            l.warn("`create_user` Username is already in use")
            return {"Error":True,"code":1001,"message":"User already exists"}
        if self.__email_taken(email):
            l.warn("`create_user` Email is already in use")
            return {"Error":True,"code":1002,"message":"Email aready in use"}
        data: dict = {}
        data["_id"] = username
        data['email'] = (self.fernet.encrypt(bytes(email,'utf-8')).decode(encoding='utf-8')) # the encrypted email, but it is less encrypted
        data['password'] = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(encoding='utf-8') # the encrypted password
        data["display-name"] = (self.fernet.encrypt(bytes(username,'utf-8')).decode(encoding='utf-8')) # their display name, I don't think this can be changed tho lol
        data["username"] = self.fernet.encrypt(bytes(original_username,'utf-8')).decode(encoding='utf-8')
        data['lang'] = language
        data['country'] = country
        data['email-hash'] = str(sha256((email+"supahcool").encode("utf-8")).hexdigest())
        data['accessed-from'] = []
        data["created"] = time_signed_up
        data["last-login"] = time.time()
        data["permissions"] = {"max-domains":3}
        data["verified"] = False
        data["domains"] = {}
        data["feature-flags"] = {}
        data["api-keys"] = {}
        data["credits"] = 200
        self.__save_data(data)
        if(not emailInstance.send_verification(username,email,original_username)):
            l.warn("`create_user` Invalid email")
            return {"Error":True,"code":1003,"message":"Invalid email"}
        return {"Error":False}

    @Session.requires_auth
    def get_gpdr(self,session:Session):
        a = self.get_data(session)
        return {"user_id":a["_id"],"location":a["country"],"creation_date":a["created"],"domains":a["domains"],"lang":a["lang"],"last_login":a["last-login"],"permissions":a["permissions"],"verified":a["verified"]}

    @l.time
    @Session.requires_auth
    def get_basic_user_data(self,session:Session) -> dict:
        """Gets the basic userdate

        Args:
            token (Token): user auth token

        Returns:
            error:
                `{"Error":True, "code":...,"message":...}`
            success:
                `{"username":str,"email":str,"lang":str,"country":str,"created":float,"verified":bool,"permissions":dict}`
            codes:
                1001 - Invalid credentials
        """
        data = self.get_data(session)
        return {
            "username": (self.fernet.decrypt(str.encode(data["display-name"]))).decode("utf-8"),
            "email": (self.fernet.decrypt(str.encode(data["email"]))).decode("utf-8"),
            "lang": data["lang"],
            "country": data["country"],
            "created": data["created"],
            "verified": data["verified"],
            "permissions":data["permissions"]
        }


    @l.time
    def remove_from_cache(self,username:str) -> None:
        try:
            del self.data_cache[username]
            l.trace(f"Deleted user {username} from cache")
        except KeyError:
            l.warn(f"Couldn't delete {username} from cache")
            pass

    @l.time
    def __add_to_cache(self,data:list,username:str) -> list:
        """Adds cache item

        Args:
            data (dict): `get_data()` of user
            token (Token): user token

        Returns:
            list: given data
        """
        l.trace(f"Adding {username} to cache")
        self.data_cache[username] = {
            "expire": time.time()+30,
            "data": data
        }
        return data

    @l.time
    @Session.requires_auth
    def __get_cache(self,session:Session) -> list:
        """Gets data from cache

        Args:
            token (Token): User auth token

        Returns:
            list: Cached user data
        """
        if(session.username not in self.data_cache):
            l.trace(f"User {session.username} not found in cache")
            return None
        if(self.data_cache.get(session.username,{}).get("expire",0) < time.time()):
            l.info(f"Cache for user {session.username} has expired")
            self.remove_from_cache(session.username)
            return None
        return self.data_cache.get(session.username,{}).get("data")

    def modify_cache(self,username: str, key: any, value: any):
        l.trace(f"Modifying cache for user {username}")
        if(username not in self.data_cache):
            l.trace(f"User {username} not found in cache")
            return None
        self.data_cache[username]["data"][key] = value
        return True

    def modify_cache_domain(self, username, key: any, value:dict):
        l.trace(f"Modifying domain {key} from cache")
        if(username not in self.data_cache):
            l.trace(f"User {username} not found in cache")
            return None
        self.data_cache[username]["data"]["domains"][key] = value
        return True

    @Session.requires_auth
    def delete_account(self,username:Session, domain:'Domain') -> dict:
        """Deletes account and domains associated WARNING: INNER FUNCTION. Call with `email.delete_user()`

        Args:
            token (Token): Auth token
            domain (Domain): Instance of Domain for deleting domains

        Returns:
            errors:
                `{"Error":True,"Errors":{domain:code, user:code}}`
            success:
                `{"Error":False}`
        """

        failed:dict={}
        user_domains:dict=self.get_data(session)["domains"]
        for key, _ in  user_domains.items():
            status=domain.delete_domain(session,key)
            if(status!=1):
                failed[key]=status

        deletion_status= self.__delete_user_from_db(session)
        if(deletion_status!=1):
            failed["user"]=deletion_status

        response:dict={"Error":False}
        if(failed.__len__()!=0):
            l.warn(f"Account deletion for user {session.username} failed ({failed})")
            response["Error"]=True,
            response["Errors"]=failed
        return response

    @l.time
    @Session.requires_auth
    def join_beta(self,session:Session) -> bool:
        self.collection.update_one({"_id":session.username},{"$set":{"beta-enroll":True}})
        self.collection.update_one({"_id":session.username},{"$set":{"beta-updated":time.time()}})
        return True

    @l.time
    @Session.requires_auth
    def leave_beta(self, session:Session) -> bool:
        self.collection.update_one({"_id":session.username},{"$set":{"beta-enroll":False}})
        self.collection.update_one({"_id":session.username},{"$set":{"beta-updated":time.time()}})
        return True

    def __get_status_data(self):
        if(self.status_data is None or self.status_data.get("expire",0) < time.time()):
            data = self.status_collection.find_one({"_id":"current"})
            if(data is None): return None
            self.status_data = data
            self.status_data["expire"] = time.time()+60
            return data
        else: return self.status_data

    def get_status(self) -> dict:
        data = self.__get_status_data()
        if(data is None): return {"reports":False}
        else: return {"reports":True, "message":data.get("message","We are experiencing heavy traffic. Features may not work correctly")}

    def delete_domain(self,domain:str, username:str) -> None:
        l.info(f"Deleting domain {domain} from user {username} from the database")
        self.collection.update_one({"_id":username}, {"$unset":{f"domains.{domain.replace('.','[dot]')}":1}})

    @Session.requires_auth
    def repair_domains(self, domainInstance:'Domain', session:Session) -> bool:
        """Repairs domains (.) in the database, and converts them to [dot]
        Non destructive action.

        self: instance of Database
        domain: instance of Domain class
        session: instance of Session class

        """
        l.info("Starting domain repair..")
        user_data:dict = self.get_data(session)
        updated_domains = {} # map of updated domains, same schema as in db
        fixed_domains:int = 0
        domain_offset:int = 0 # duplicate domains that a hashmap will purge

        for domain in user_data["domains"].copy():
            if domain.replace(".","[dot]") in updated_domains:
                l.warn(f"Duplicate domain found {domain}")
                domain_offset += 1
                continue

            if "." in domain:
                updated_domains[domain.replace(".","[dot]")] = user_data["domains"][domain]
                l.info(f"Fixed invalid db schema for domain {domain}")
                fixed_domains += 1
            else:
                updated_domains[domain] = user_data["domains"][domain]

            domain_id = updated_domains[domain.replace(".","[dot]")]["id"]

            if domain_id is None or domain_id == "":
                resp = domainInstance.repair_domain_id(
                    session,
                    domain,
                    updated_domains[domain.replace(".","[dot]")]["type"],
                    updated_domains[domain.replace(".","[dot]")]["ip"] # content of the domain, stupid db schema
                )

                if not resp["success"]:
                    l.error("Failed to repair domain id")
                else:
                    l.info(f"Succesfully fixed id of domain {domain}")
                    edited_stats = updated_domains[domain.replace(".","[dot]")]
                    edited_stats["id"] = resp["domain"]["id"] # type: ignore
                    edited_stats["ip"] = resp["domain"]["content"] # type: ignore
                    updated_domains[domain.replace(".","[dot]")] = edited_stats

        if fixed_domains == 0:
            l.info("Didn't fix any domains")
            return False

        l.info(f"Fixed {fixed_domains} domains")

        if len(updated_domains) != (len(user_data["domains"]) - domain_offset):
            l.error(f"`repair_domains` updated lenght is not same as original ({list(updated_domains.keys())} vs {list(user_data['domains'].keys())}), aborting")
            return False

        self.update_data(username=session.username,key="domains",value=updated_domains)
        return True
