from __future__ import annotations
import requests
from requests import Response
import time
import string
from .Session import Session
from .Logger import Logger
from typing import TYPE_CHECKING
import os
from dotenv import load_dotenv
load_dotenv()

l:Logger = Logger("Domain.py", os.getenv("DC_WEBHOOK"),os.getenv("DC_TRACE"))
class Domain:
    def __init__(self,db:'Database',email:str,cf_key_w:str, cf_key_r,zone_id):
        self.db:'Database'=db
        self.email = email
        self.cf_key_w = cf_key_w
        self.cf_key_r = cf_key_r
        self.zone_id:str=zone_id


    @staticmethod
    @l.time
    def is_domain_valid(domain_: str) -> bool:
        """Checks if domain is vlaid

        Args:
            domain_ (str): domain

        Returns:
            bool: if domain is valid
        """
        allowed = list(string.ascii_letters)
        allowed.extend(list(string.digits))
        allowed.extend([".","-"])
        valid = all(c in allowed for c in domain_) # this *might* work, super hacky tho
        return valid

    @l.time
    def __add_domain_to_user(self,session: Session, domain: str, content: str=None,  type_: str=None, domain_id: str=None,proxied:bool=False) -> bool:
        l.info(f"`__add_domain_to_user` adding domain {domain} to {session.username}. Called with domain {domain} and id {domain_id}")
        domain = domain.replace(".","[dot]")
        data = self.db.get_data(session)
        l.trace(f"User domains: {data['domains']}")
        if(domain.replace("[dot]",".") not in data["domains"] and domain_id is not None):
            l.info(f"`__add_domain_to_user` registering domain {domain}")
            domain_data = {
                "ip":content,
                "type":type_,
                "registered":time.time(),
                "id":domain_id,
                "proxy":proxied
            }
            self.db.add_domain(session,domain,domain_data)
            return True
        l.info(f"`__add_domain_to_user` modifying domain {domain}")

        domain_data = data["domains"][domain.replace("[dot]",".")] # for some reason, get_data returns domains marked as [dot] as .
        if(content!=None):
            domain_data["ip"]=content
            l.trace("`__add_domain_to_user` updating ip since one is specified")
        if(type_!=None):
            domain_data["type"]=type_
            l.trace("`__add_domain_to_user` updating ip since one is specified")
        if(proxied is not None):
            domain_data["proxy"]=proxied
            l.trace("`__add_domain_to_user` updating proxy since one is specified")
        self.db.modify_domain(session,domain,domain_data)
        return True

    def __add_dommain_to_user_api(self,api:'Api', domain:str, content:str=None, type_:str=None, domain_id:str=None) -> bool:
        if(domain not in api.domains):
            domain_data = {
                "ip":content,
                "type":type_,
                "registered":time.time(),
                "id":domain_id,
                "proxy":False
            }
            self.db.collection.update_one({"_id":api.username},{"$set":{f"domains.{domain.replace('.','[dot]')}":domain_data}})
            return True

        domain_data = api.domains.get(domain)
        if(content!=None):
            domain_data["ip"]=content
        if(type_!=None):
            domain_data["type"]=type_
        self.db.collection.update_one({"_id":api.username},{"$set":{f"domains.{domain.replace('.','[dot]')}":domain_data}})
        return True

    @l.time
    @Session.requires_auth
    def delete_domain(self,session:Session, domain: str) -> int:
        """Deletes specified domain

        Returns:
            int: -1 not owning domain, 0 passowrd or user not correct, 1 succeed
        """
        domains: dict = self.get_user_domains(self.db,session)
        if(domain.replace("[dot]",".") not in domains):
            l.info(f"Domain {domain} not in domains of user {session.username}")
            return -1
        headers: dict = {
            "Content-Type": "application/json",
            "Authorization": "Bearer "+self.cf_key_w, # cloudflare write token
            "X-Auth-Email": self.email
        }
        record_not_exist = False
        response = requests.delete(f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records/{domains[domain.replace('[dot]','.')]['id']}",headers=headers)
        if(response.json().get("success") is False):
            if(response.json().get("errors",[{}])[0].get("code") == 81044): record_not_exist = True
        if(record_not_exist):
            l.warn("Record does not exist on CloudFlare, but does on Database. Ignoring...")
        self.db.delete_domain(domain.replace("[dot]","."), session.username)
        l.info(f"Succesfully deleted domain {domain}")
        if response.status_code != 200:
            l.warn(f"`delete_domain` response status was not 200 ({response.json()})")
        return 1

    @Session.requires_auth
    def get_user_domains(self,database, session:Session) -> dict:
        """Get user domains

        Args:
            database (Database): instance of database
            token (Token): user auth

        Returns:
            error:
                `{"Error":True,"code":...,"message":...}`
            success:
                `{domains:dict}`
            codes:
                1001 - invalid creds
                1002 - No domains

        NOTE: Subdomains will be returned as a.b.c, not a[dot]b[dot]c

        """
        data = self.db.get_data(session=session)
        ran_repair: bool = False
        if(data.get("domains",[]).__len__()!=0):
            domains = data["domains"]
            for domain in list(domains.keys()):
                if "." in domain and not ran_repair:
                    self.db.repair_domains(session)
                    ran_repair = True
                domains[domain.replace("[dot]",".")] = domains.pop(domain)
            return domains
        l.trace(f"User {session.username} has no domains")
        return {"Error":True,"code":1002,"message":"No domains"}

    def check_domain(self,domain: str, domains:dict={}, type_: str = "A") -> int:
        """Checks if domain is valid, and not in use

        Args:
            domain (str): specified domain (**without** .frii.site suffix)
            domains (dict, optional): domains that user has (`get_data()["domains]`). if is None, the domain is considered invalid if there is another domain linked to it (secondary.primary.frii.site) since the server cannot verify if user owns primary.frii...
            type_ (str, optional): Type of the record in uppercase, supported: A,CNAME,TXT,NS. Defaults to "A".

        Returns:
            int: 1 - Success
            int: 0 - domain is not valid
            int: -1 - does not own a part of the domain (ex: mydomain.another.frii.site, where user does NOT own another.frii.site)
            int: -2 - domain is already in use
        """
        domain = domain.replace("[dot]",".")
        headers = {
            "X-Auth-Email": self.email,
            "Authorization": "Bearer "+self.cf_key_r
        }
        if(type_ != "TXT"):
            l.info(f"Type is not TXT, continuing check #1")
            if(not Domain.is_domain_valid(domain)):
                return 0

        domain_parts = domain.split(".")
        req_domain:str=domain_parts[-1]
        if(req_domain!="" and domain_parts.__len__()!=1 and req_domain not in domains):
            l.info(f"User needs to own {req_domain} before registering {domain}!")
            return -1
        if(domain not in domains):
            response:Response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records?name={domain.replace('[dot]','.')+'.frii.site'}", headers=headers) # is the domain available
            if(list(response.json().get("result",[])).__len__()!=0):
                l.info(f"Domain {domain} is not available on CloudFlare")
                return -2
        l.trace(f"Domain check for {domain} succeeded")
        return 1


    @Session.requires_auth
    def modify(self,database: 'Database', domain: str, session:Session, new_content: str, type_:str, proxied:bool=False) -> dict:
        """Modify a domain

        Args:
            database (Database): instance of `Database` class
            domain (str): The domain wish to modify (without .frii.site suffix)
            token (Token): auth token
            new_content (str): new content of the domain
            type_ (str): type of the domain

        Returns:
            error:
                `{"Error":True, "message":.., "code":...}`
            success:
                `{"Error":False,"message":"Succesfully modified domain"}`
            codes:
                1005: Domain not in domains
                1004: Invalid credentials
                10x1: Invalid domain (x being reason, consult `self.check_domain()`)
                1xxx: Cloudflare api issue
        """
        l.trace(f"Modifying {domain} with type {type_} and content of {new_content}")
        data: dict = self.db.get_data(session)
        domains:dict = self.get_user_domains(self.db,session=session)
        l.trace(f"Requested domain {domain.replace('[dot]','.')}")
        if(domain.replace("[dot]",".") not in domains):
            l.warn(f"User does not own {domain}")
            return {"Error":True,"message":"No permissions","code":1005}

        check_domain_status=self.check_domain(domain,domains,type_)
        if(check_domain_status!=1):
            l.info(f"Domain check resulted in code {check_domain_status}")
            return {"Error":True, "message":f"Invalid domain ({int(f'10{check_domain_status*-1}1')})", "code":int(f"10{check_domain_status*-1}1")}
        data_ = {
            "content": new_content,
            "name": domain.replace("[dot]",".") ,
            "proxied": proxied,
            "type": type_, # from Dan: i added the type so you can add more records lol
            "comment": "Changed by "+(self.db.fernet.decrypt(str.encode(data['display-name']))).decode("utf-8") # a handy dandy lil message
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer "+self.cf_key_w,
            "X-Auth-Email": self.email
        }
        response:Response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records/{domains[domain.replace('[dot]','.')]['id']}",json=data_,headers=headers,timeout=20)
        if(response.status_code==200):
            self.__add_domain_to_user(session=session,domain=domain,content=new_content,domain_id=None,type_=type_,proxied=proxied)
            l.info(f"Modified {domain} for user {session.username}")
            return {"Error":False,"message":"Succesfully modified domain"}
        else:
            l.warn(f"`modify` CloudFlare didn't respond with a 200. Id used: {domains[domain.replace('[dot]','.')]['id']} ({response.json()})")
            return {"Error":True,"code":int(f"1{response.status_code}"),"message":"Backend api failed to respond with a valid status code."}

    def modify_with_api(self,database: 'Database', domain: str, apiKey:'Api', new_content:str, type_: str)->dict:
        required_permissions = apiKey.required_permissions(domain,type_,new_content)
        if(domain not in apiKey.affected_domains): return {"Error":True,"code":1001,"message":"API key does not have sufficent permissions"}
        for perm in required_permissions:
            if(perm not in apiKey.permissions):
                l.info("`modify_with_api` API Key does not have the correct permissions")
                return {"Error":True,"code":1001,"message":"API key does not have sufficent permissions"}

        domain_stauts = self.check_domain(domain,apiKey.domains,type_)
        if(domain_stauts!=1): return {"Error":True,"code":1002,"message":f"Invalid domain ({domain_stauts})"}
        data_ = {
            "content": new_content,
            "name": domain.replace("[dot]",".") ,
            "proxied": False,
            "type": type_,
            "comment": "Changed with api key"
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer "+self.cf_key_w,
            "X-Auth-Email": self.email
        }
        response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records/{apiKey.get_domain_id(domain)}",json=data_,headers=headers,timeout=20)
        if(response.status_code!=200):
            l.warn(f"`modify_with_api` resulted in a status code of {response.status_code}")
            return {"Error":True,"code":1003,"message":"Backend refused to accept domain change"}
        self.__add_dommain_to_user_api(apiKey,domain,new_content,type_,response.json().get("result",{}).get("id"))
        l.info(f"Modified domain {domain} with API")
        return {"Error":False,"code":1000,"message":"Succesfully changed domain"}

    @Session.requires_auth
    def register(self,domain: str, content: str, session: Session, type_: str, proxied:bool) -> dict:
        """Registers a domain

        Args:
            domain (str): domain to register (without .frii.site suffix)
            content (str): the content of the domain
            token (Token): authorization token of user
            type (str): what type of domain it is

        Returns:
            if error:
                `{"Error":True,"code":...,"message":...}`
            if success:
                `{"Error":False,"message":"Registered domain succesfully"}`
            codes:
                1000: Wrong creds
                1001: Invalid type
                1002: User not verified
                1003: domain limit
                10x4: Domain is not valid where `x*-1` is the reason (refer to `self.check_domain()`)
        """

        if(type_.lower() not in ["a","cname","txt","ns"]):
            l.info(f"{type_} is not a valid type")
            return {"Error":True,"code":1001,"message":f"Invalid type: {type_}"}

        amount_of_domains: int = self.get_user_domains(self.db,session=session).__len__()
        if(amount_of_domains > self.db.get_data(session).get("permissions",{}).get("max-domains",4)):
            l.info(f"`register` maximum domain limit reached")
            return {"Error":True,"code":1003,"message":"You have reached your domain limit"}

        domain_check:int=self.check_domain(domain,self.get_user_domains(self.db,session=session),type_)
        if(domain_check!=1):
            l.info(f"`regster` failed: {domain} is invalid (reason no {domain_check})")
            return {"Error":True,"code":int(f"10{domain_check*-1}4"),"message":f"Domain is not valid. Reason No. {domain_check}"}

        headers = {
            "Content-Type":"application/json",
            "Authorization": "Bearer "+self.cf_key_w,
            "X-Auth-Email": self.email
        }

        if(type_=="CNAME" or type_=="NS"): l.info(f"Changing content to example.com since domain is {type_} type"); content="example.com"
        data_ = {
            "content": content,
            "name": domain.replace("[dot]","."), # because 'domain' is *only* the subdomain (example.frii.site->example)
            "proxied": proxied, # so cloudflare doesn't proxy the content
            "type": type_.strip(), # the type of the record.
            "comment": "Issued by "+(self.db.fernet.decrypt(str.encode(self.db.get_data(session)["display-name"]))).decode("utf-8"), # just a handy-dandy lil feature that shows the admin (me) who registered the domain
            "ttl": 1 # auto ttl
        }
        response = requests.post(f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records",headers=headers,json=data_)
        if(response.status_code==200):
            l.info(f"Registered domain {domain} succesfully")
            self.__add_domain_to_user(session,domain,content,type_,response.json().get("result",{}).get("id"), proxied)
        else:
            l.error(f"Registering domain cloudflare returned {response.status_code}")
            return {"Error":True,"code":1030,"message":"Cloudflare did not accept domain"}
        return {"Error":False,"code":0,"message":"Succesfully registered"}
