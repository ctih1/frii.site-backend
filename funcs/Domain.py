from __future__ import annotations
from ast import Delete
import requests
from requests import Response
import time
import string
from .Session import Session
from .Logger import Logger
from .Api import Permission
import re
from .DNS import DNS, ModifyError, RegisterError
from typing import TYPE_CHECKING
import os
from typing import TypedDict, NotRequired
from dotenv import load_dotenv
load_dotenv()

DomainType = TypedDict(
    "DomainType", {"name":str, "type":str}
)

RepairDomainType = TypedDict(
    "RepairDomainType", {
        "id":str, "content":str
    }
)

RepairDomainStatus = TypedDict(
    "RepairDomainStatus", {
        "success":bool,
        "json":NotRequired[dict],
        "domain": NotRequired[RepairDomainType]
    }
)

l:Logger = Logger("Domain.py", os.getenv("DC_WEBHOOK"),os.getenv("DC_TRACE"))
class Domain:
    def __init__(self,db:'Database',email:str,cf_key_w:str, cf_key_r,zone_id):
        self.db:'Database'=db
        self.email = email
        self.cf_key_r = cf_key_r
        self.cf_key_w = cf_key_w
        self.zone_id = zone_id
        self.dns = DNS(cf_key_w, zone_id, email)


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
            int:-2 domain repair failed, -1 not owning domain, 0 passowrd or user not correct, 1 succeed
        """
        domains: dict = self.get_user_domains(self.db,session)
        if(domain.replace("[dot]",".") not in domains):
            l.info(f"Domain {domain} not in domains of user {session.username}")
            return -1
        record_not_exist = not DNS(self.cf_key_w,self.zone_id, self.email).delete(
            domains.get(domain.replace("[dot]","."))["id"] # type: ignore
        )
        if record_not_exist:
            l.warn("Record does not exist on CloudFlare, but does on Database. Starting repair...")
            result = self.repair_domain_id(session, domain, "A" ,"0.0.0.0", mode="delete")
            if not result["success"]:
                l.warn("Failed to fix domain")
                return -2

        l.info(f"Succesfully deleted domain {domain}")
        self.db.delete_domain(domain.replace("[dot]","."), session.username)
        return 1

    @Session.requires_auth
    def get_user_domains(self,database, session:Session, skip_fix:bool=False) -> dict:
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
                if "." in domain and not ran_repair and not skip_fix:
                    self.db.repair_domains(self,session)
                    ran_repair = True
                domains[domain.replace("[dot]",".")] = domains.pop(domain)
            return domains
        l.trace(f"User {session.username} has no domains")
        return {"Error":True,"code":1002,"message":"No domains"}

    def check_domain(self,domain: str, domains:dict={}, type_: str = "A") -> int:
        """Checks if domain is valid, and not in use

        Checks:
            * Is domain syntaxically valid (punnycode)
            * Subdomain verification
            * User does not own domain

        Args:
            domain (str): specified domain (**without** .frii.site suffix)
            domains (dict, optional): domains that user has (`get_data()["domains]`). if is None, the domain is considered invalid if there is another domain linked to it (secondary.primary.frii.site) since the server cannot verify if user owns primary.frii...
            type_ (str, optional): Type of the record in uppercase, supported: A,CNAME,TXT,NS. Defaults to "A".

        Returns:
            int: 1 - Success
            int: 0 - domain is not valid
            int: -1 - does not own a part of the domain (ex: mydomain.another.frii.site, where user does NOT own another.frii.site)
            int: -2 - domain is already in use
            int: -3 - not valid type
        """


        domain = domain.replace("[dot]",".")
        if type_.lower() not in ["a","cname","txt","ns"]:
            return -3

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


        if domain.replace(".","[dot]") not in domains:
            if self.db.collection.find_one({f"domains.{domain.replace('.','[dot]')}":{"$exists":True}}) is not None:
                l.warn("Domain is already in use (database)")
                return -2

            response:Response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records?name={domain.replace('[dot]','.')+'.frii.site'}", headers=headers) # is the domain available
            if(list(response.json().get("result",[])).__len__()!=0):
                if len(domains) == 0:
                    l.info("Domains is an empty object")
                REGEX_MATCH_STRING = r"\b[a-fA-F0-9]{64}\b"

                domain_comment = response.json().get("result")[0]["comment"]
                regex_matches = re.findall(REGEX_MATCH_STRING, domain_comment)

                username = regex_matches[0]

                user_domains = self.db.collection.find_one({"_id":username}) or {}.get("domains",{})
                user_owns_domain = user_domains.get(domain.replace(".","[dot]")) is not None and user_domains.get(domain.replace("[dot]",".")) is None
                if user_owns_domain:
                    l.info(f"Domain {domain} is not available on CloudFlare, and user does not own it")
                    return -2
                else:
                    l.info(f"Ignoring expired domain for username {username}")
                    dns = DNS(self.cf_key_w, self.zone_id, self.email)
                    domain_id = dns.find_domain_id(domain=domain.replace("[dot]","."))
                    dns.delete(domain_id)

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

        l.info(f"Modifying domain {domain}")

        domains:dict = self.db.get_data(session)["domains"]
        print(domains)
        l.trace(f"Requested domain {domain.replace('[dot]','.')}")

        if domain not in domains: # stupid fucking hack no idea why db returns domains as . sometimes
            l.warn(f"User does not own {domain}")
            return {"Error":True,"message":"No permissions","code":1005}

        check_domain_status = self.check_domain(
            domain.replace(".","[dot]"),
            domains,
            type_
        )

        if check_domain_status!=1:
            l.info(f"Domain check resulted in code {check_domain_status}")

            check_domain_reason_int = int(f'10{check_domain_status*-1}1')
            return {"Error":True, "message":f"Invalid domain ({check_domain_reason_int})", "code":check_domain_reason_int}

        try:
            dns_status = self.dns.modify_domain(
                domains[domain]["id"],
                new_content,
                type_,
                domain,
                f"Updated with Session based auth ({session.username})"
            )

            self.__add_domain_to_user(
                session,
                domain,
                new_content,
                type_,
                dns_status["id"],
                proxied
            )
            return {"Error":False, "code":0, "message":"Domain modified"}

        except ModifyError as e:
            l.error(f"Failed to register domain ({e.json})")
            if not e.json["errors"][0]["code"] == 10000:
                return {"Error":True,"code":1400,"message":"Backend api failed to respond with a valid status code."}

            resp = self.repair_domain_id(session,domain.replace("[dot]","."),type_,new_content)
            if not resp["success"]:
                l.error("Failed to repair domains")
                return {"Error":True,"code":1401,"message":"Fixing domain failed"}


            cleaned = domains[domain]
            cleaned["ip"] = resp["domain"]["id"] # type: ignore
            cleaned["ip"] = resp["domain"]["content"] # type: ignore

            self.db.modify_domain( # retry after fixing domain
                session, domain, cleaned
            )


    def modify_with_api(self,database: 'Database', domain: str, apiKey:'Api', new_content:str, type_: str)->dict:
        domain = domain.replace(".","[dot]")
        required_permissions = apiKey.required_permissions(domain,type_,new_content)

        if domain not in apiKey.affected_domains:
            return {"Error":True,"code":1001,"message":"API key does not have sufficent permissions for this domain"}

        for perm in required_permissions:
            if perm not in apiKey.permissions:
                l.info("`modify_with_api` API Key does not have the correct permissions")
                return {"Error":True,"code":1001,"message":f"API is missing permission(s) ({perm})"}

        domain_stauts = self.check_domain(domain,apiKey.domains,type_)
        if domain_stauts!=1:
            return {"Error":True,"code":1002,"message":f"Invalid domain ({domain_stauts})"}


        try:
            dns_status = self.dns.modify_domain(
                apiKey.domains[domain]["id"],
                new_content,
                type_,
                domain,
                f"Updated with Session based auth ({apiKey.username})"
            )

            self.__add_dommain_to_user_api(
                apiKey,
                domain,
                new_content,
                type_,
                dns_status["id"],
            )
            return {"Error":False,"code":1000,"message":"Succesfully changed domain"}
        except ModifyError as e:
            return {"Error":True, "code": 1003, "message": "DNS Server refused to accept changes"}

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

        l.info(f"Registering domain {domain}")

        amount_of_domains: int = self.get_user_domains(self.db,session=session,skip_fix=True).__len__()
        user_max_domains:int = self.db.get_data(session).get("permissions",{}).get("max-domains",4)

        if amount_of_domains > user_max_domains:
            l.info("`register` maximum domain limit reached")
            return {"Error":True,"code":1003,"message":"You have reached your domain limit"}

        domain_check:int=self.check_domain(
            domain,
            self.get_user_domains(
                self.db,
                session=session,
                skip_fix=True
            ),
            type_
        )

        if domain_check!=1:
            l.info(f"`regster` failed: {domain} is invalid (reason no {domain_check})")
            return {"Error":True,"code":int(f"10{domain_check*-1}4"),"message":f"Domain is not valid. Reason No. {domain_check}"}

        try:
            result = self.dns.register_domain(
                domain,
                content,
                type_,
                comment=f"Registered through Sessions {session.username}"
            )
        except RegisterError as e:
            l.error(f"Registering domain failed {e.json}")
            return {"Error":True,"code":1030,"message":"DNS denied request"}


        l.info(f"Registered domain {domain} succesfully")
        self.__add_domain_to_user(
            session,
            domain,
            content,
            type_,
            result["id"],
            proxied
        )

        return {"Error":False,"code":0,"message":"Succesfully registered", "id":result["id"]}



    def register_with_api(self,domain:str, content: str, apiKey: 'Api', type_: str):
        domain = domain.replace(".","[dot]")

        if "".join(domain.split("[dot]")[1:]) not in apiKey.affected_domains:
            return {"Error":True,"code":1001,"message":f"API key does not have sufficent permissions for this domain {domain.split('[dot]')[1:]}"}

        if Permission.CREATE not in apiKey.permissions:
            l.info("`modify_with_api` API Key does not have the correct permissions")
            return {"Error":True,"code":1001,"message":"API is missing permission(s) (create subdomains)"}

        data = self.db.collection.find_one({"_id":apiKey.username})


        amount_of_domains: int = data["domains"].__len__()
        user_max_domains:int = data.get("permissions",{}).get("max-domains",4)

        if amount_of_domains > user_max_domains:
            l.info("`register` maximum domain limit reached")
            return {"Error":True,"code":1003,"message":"You have reached your domain limit"}

        domain_check:int=self.check_domain(
            domain,
            apiKey.affected_domains,
            type_
        )

        if domain_check!=1:
            l.info(f"`regster` failed: {domain} is invalid (reason no {domain_check})")
            return {"Error":True,"code":int(f"10{domain_check*-1}4"),"message":f"Domain is not valid. Reason No. {domain_check}"}

        try:
            result = self.dns.register_domain(
                domain,
                content,
                type_,
                comment=f"Registered through API {apiKey.username}"
            )

        except RegisterError as e:
            l.error(f"Registering domain failed {e.json}")
            return {"Error":True,"code":1030,"message":"DNS denied request"}

        l.info(f"Registered domain {domain} succesfully")
        self.__add_dommain_to_user_api(
            apiKey,
            domain,
            content,
            type_,
            result["id"],
        )

        return {"Error":False,"code":0,"message":"Succesfully registered", "id":result["id"]}


    @Session.requires_auth
    def repair_domain_id(self,session:Session, domain:str, type_:str, content:str, mode="register") -> RepairDomainStatus:
        # https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-list-dns-records
        #
        response = requests.get(
            f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records?name={domain.replace('[dot]','.') + '.frii.site'}",
            headers={
                "Authorization": "Bearer "+self.cf_key_w,
                "X-Auth-Email": self.email
            }
        )

        if not response.ok or response.json()["result_info"]["total_count"] == 0:
            l.error(f"Failed to recover id of {domain}, trying to register...")
            if mode == "register":
                status = self.register(domain,content,session,type_,False)
                if not status["Error"]:
                    return RepairDomainStatus(
                        success=True,
                        domain=RepairDomainType(
                            id=status["id"], content=content
                        )
                    )
                return RepairDomainStatus(
                        success=False,
                        json={"error":"Failed to regsiter domain"}
                    )
            elif mode == "delete":  # record does not exist, so we dont have to delete it
                return RepairDomainStatus(
                    success=True,
                    json={"error":""}
                )

        l.info(f"Succesfully repaired domain {domain}")
        domain_result = response.json()["result"][0]

        return RepairDomainStatus(
            success=True,
            domain=RepairDomainType(id=domain_result["id"], content=domain_result["content"])
        )
