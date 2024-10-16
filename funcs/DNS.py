import json
from .Logger import Logger
import requests
from typing import TypedDict

DomainResponse = TypedDict(
    "DomainResponse",
    {
        "id":str
    }
)

l:Logger = Logger("DNS.py","None","None") # discod webhook set as None

class ModifyError(Exception):
    def __init__(self, message:str,json:dict):
        self.json = json
        super().__init__(message)

class RegisterError(Exception):
    def __init__(self, message:str, json:dict):
        self.json = json
        super().__init__(message)


class DNS:
    def __init__(self, api_key:str, zone_id:str, email:str):
        self.key = api_key
        self.zone_id = zone_id
        self.email = email

    def modify_domain(self, domain_id:str, content:str, type_:str, domain:str, comment:str) -> DomainResponse:
        domain = domain.replace("[dot]",".")

        response = requests.patch(
            f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records/{domain_id}",
            data = json.dumps({
                "content": content,
                "name": domain,
                "proxied":False,
                "type": type_,
                "comment": comment
            }),
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Bearer "+self.key,
                "X-Auth-Email": self.email
            },
            timeout = 10
        )

        if not response.ok:
            raise ModifyError(
                message = f"Failed to modify domain {domain}",
                json = response.json()
            )

        id = response.json().get("result",{}).get("id")
        return DomainResponse(
            id = id
        )


    def register_domain(self, domain:str, content:str, type_:str, comment:str) -> DomainResponse:
        domain = domain.replace("[dot]",".")

        if type_=="CNAME" or type_=="NS" and content == "0.0.0.0":
            l.info(f"Changing registration content of {domain} to example.com due to types")
            content = "example.com"

        response = requests.post(
            f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records",
            headers = {
                "Content-Type":"application/json",
                "Authorization": "Bearer "+self.key,
                "X-Auth-Email": self.email
            },
            data = json.dumps({
                "content": content,
                "name": domain,
                "proxied":False,
                "type": type_,
                "comment":comment,
                "ttl": 1 # automatic time to live for the record
            })
        )

        if not response.ok:
            l.error(f"Failed to register domain {domain}")
            raise RegisterError(
                message = f"Failed to register domain {domain}",
                json = response.json()
            )

        id = response.json().get("result",{}).get("id")
        return DomainResponse(
            id=id
        )
