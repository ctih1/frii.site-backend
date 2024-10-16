from __future__ import annotations
from .Utils import generate_random_string
from .Session import Session
from .Logger import Logger
import time
import resend
from .Session import Session
from hashlib import sha256
import bcrypt
from typing import TYPE_CHECKING
import datetime
if TYPE_CHECKING:
    from Database import Database
    from Domain import Domain

import os
from dotenv import load_dotenv
load_dotenv()

l = Logger("Email.py",os.getenv("DC_WEBHOOK"),os.getenv("DC_TRACE"))

class Email:
    def __init__(self,api_key:str,db):
        resend.api_key = api_key
        self.db:Database = db
        self.codes:dict={}
        self.del_codes:dict={}
        self.pass_codes:dict={}

        self.sync_codes()

    @l.time
    def sync_codes(self):
        cursor=self.db.codes.find()
        results_processed:int=0
        for result in cursor:
            if(result.get("type",None)=="verif"):
                results_processed+=1
                self.codes[result["_id"]] = {}
                self.codes[result["_id"]]["account"]=self.db.fernet.decrypt(str.encode(result["account"])).decode("utf-8")
                self.codes[result["_id"]]["expire"]=result["expire"]
            if(result.get("type",None)=="delete"):
                results_processed+=1
                self.del_codes[result["_id"]] = {}
                self.codes[result["_id"]]["auth-token"]=self.db.fernet.decrypt(str.encode(result["auth-token"])).decode("utf-8")
                self.codes[result["_id"]]["expire"]=result["expire"]
        l.info(f"Processed a total of {results_processed} codes")

    def send_verification(self,username:str,target:str,display_name:str) -> bool:
        l.info(f"Sending verification to user {username}")
        expire_time = 45*60
        random_pin = generate_random_string(32)
        self.codes[random_pin] = {}
        self.codes[random_pin]["account"]=username
        self.codes[random_pin]["expire"]=time.time()+expire_time
        l.info(f"Verification packet: {self.codes[random_pin]}")
        self.db.codes.create_index("expiresAfter",expireAfterSeconds=1)
        self.db.codes.insert_one({
            "_id":random_pin,
            "type":"verif",
            "expire":self.codes[random_pin]["expire"],
            "account":str(self.db.fernet.encrypt(bytes(username,"utf-8")).decode(encoding='utf-8')),
            "expiresAfter":datetime.datetime.now() + datetime.timedelta(minutes=5)
        })
        try:
            r = resend.Emails.send({
                "from": 'send@frii.site',
                "to": target,
                "subject": "Verify your account",
                "html":
                '<html><h1>Hello $username!</h1> <h2>Click <a href="https://api.frii.site/verification/$code">here</a> to verify your account</h2> <h3>Do <b>NOT</b> share this code!</h3> <p>This code will expire in 45 minutes.</p> <p>Link not working? Copy the text below into your browser address bar</p>https://api.frii.site/verification/$code</div></html>'.replace("$username",display_name).replace("$code",random_pin)
            })
        except resend.exceptions.ResendError as e:
            l.error(f"Failed to send email {e}")
            return False
        return True

    def verify_email(self,code: str) -> bool:
        """Confirms if email verification succeeded

        Args:
            code (str): verification code

        Returns:
            bool: if verification succeeded
        """
        if(code not in self.codes): return False
        if not round(time.time()) < self.codes[code]["expire"]: return False
        l.info(f"Code is valid, verifying {self.codes[code]}")
        self.db.update_data(username=self.codes[code]["account"],key="verified",value=True)
        self.db.modify_cache(self.codes[code]["account"],"verified",True) # invalidate cache for user
        del self.codes[code]
        return True


    @Session.requires_auth
    def send_delete_email(self,email:str,session:Session,displayname:str) -> bool:
        """Send an account deletion email to user

        Args:
            email (str): decrypted email of account
            token (Token): user authentication
            displayname (str): the name that will be shown on the email

        Returns:
            bool: if the email was sent.
        """
        random_pin = generate_random_string(128)
        self.del_codes[random_pin] = {}
        self.del_codes[random_pin]["auth-token"]=session.id
        self.del_codes[random_pin]["expire"] = time.time()+30*60
        r = resend.Emails.send({
            "from":"send@frii.site",
            "to": email,
            "subject": "Confirm your account deletion",
            "html": '<html><div class="holder"> <h1>Hello $username.</h1> <h2>Click <a href="https://api.frii.site/account-deletion/$code">here</a> to confirm the deletion of your account.</h2> <h3>Do <b>NOT</b> share this code!</h3> <p>This code will expire in 30 minutes.</p> <p>Link not working? Copy the text below into your browser address bar</p>https://api.frii.site/account-deletion/$code</div></html>'.replace("$code",random_pin).replace("$username",displayname)
        })
        self.db.codes.insert_one({
            "_id":random_pin,
            "type":"delete",
            "expire":self.del_codes[random_pin]["expire"],
            "auth-token":str(self.db.fernet.encrypt(bytes(session.username,"utf-8")).decode(encoding='utf-8')),
            "expiresAfter":datetime.datetime.now() + datetime.timedelta(minutes=5)
        })
        return True

    @Session.requires_auth
    def initiate_account_deletion(self,session:Session)-> bool:
        data = self.db.get_basic_user_data(session)
        self.send_delete_email(data["email"],session,data["username"])
        return True

    def delete_user(self,code:str, __domain:Domain, ip) -> dict:
        """Delete users domains and account

        Args:
            code (str): verification code

        Returns:
            error:
                `{"Error":True,"code":...,"message":...}`
            success:
                `{"Error":False...}`
            codes:
                1001 - Invalid code
                1002 - expired
        """
        if (code not in self.del_codes): {"Error":True,"code":1001,"message":"Invalid code"}
        if (not round(time.time()) < self.del_codes[code]["expire"]): del self.del_codes[code]; return {"Error":True,"code":1002,"message":"Code expired"}
        return self.db.delete_account(Session(self.del_codes[code]["auth-token"],ip,self.db),__domain)

    def resend_email(self,username) -> bool:
        """Resends an email to user

        Args:
            token (Token): user authorization token

        Returns:
            bool: if email was sent
        """
        start = time.time()
        data:dict=self.db.collection.find_one({"_id":username}) # type: ignore
        if data is None:
            l.info("User not found, returning False")
            return False
        if(data["verified"]):
            l.info("User is already verified...")
            return False
        return self.send_verification(
            username,
            self.db.fernet.decrypt(data["email"].encode("utf-8")).decode("utf-8"),
            data["username"]
        )

    def initiate_recovery(self,username:str) -> bool:
        """Sends a password recovery email to email

        Args:
            username (str): accounts username

        Returns:
            bool: if email was sent
        """
        hash_username = sha256(username.encode("utf-8")).hexdigest()
        start = time.time()

        user_data = self.db.collection.find_one({"_id":hash_username})
        print(f"Getting data from db: {time.time()-start}")

        email = self.db.fernet.decrypt(str.encode(user_data["email"])).decode("utf-8")

        random_pin = generate_random_string(32)
        try:
            r = resend.Emails.send({
                "from":"send@frii.site",
                "to": email,
                "subject": "Password recovery",
                "html": '<html><h1>Hello dear frii.site user.</h1> <h2>Click <a href="https://www.frii.site/account/recover?c=$code">here</a> to reset the password of your account.</h2> <h3>Do <b>NOT</b> share this code!</h3> <p>Link not working? Copy the text below into your browser address bar</p> https://www.frii.site/account/recover?c=$code </div></html>'.replace("$code",random_pin)
            })
        except resend.exceptions.ResendError:
            print("Email error")
            return False
        self.pass_codes[random_pin] = {}
        self.pass_codes[random_pin]["expire"] = time.time()+30*60
        self.pass_codes[random_pin]["account"] = hash_username
        return True

    def reset_password(self,code:str,new_password:str) -> bool:
        if(self.pass_codes.get(code,None) is None): return False
        new_password = str(sha256(new_password.encode("utf-8")).hexdigest())
        password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode(encoding='utf-8')
        self.db.collection.update_one({"_id":self.pass_codes[code]["account"]},{"$set":{"password":password}})

        del self.pass_codes[code]
        return True
