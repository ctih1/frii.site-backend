import os
import requests # type: ignore[import-untyped]
import json
from pymongo import MongoClient
from database.tables.domains import Domains, RepairFormat, DomainFormat
from dns_.exceptions import DNSException
from dns_.validation import Validation

class DNS:
    def __init__(self, domains:Domains):
        """Documentation for functions were created by ai.
        """
        self.table = domains
        self.zone_id:str = os.getenv("ZONE_ID") or ""
        self.key:str = os.getenv("CF_KEY_W") or ""
        self.email:str = os.getenv("EMAIL") or ""

    def get_id(self, name:str, type:str|None= None, value:str|None=None) -> str | None:
        """
        Retrieves the ID of a DNS record from Cloudflare.
        Args:
            name (str): The name of the DNS record.
            type (str | None, optional): The type of the DNS record. Defaults to None.
            value (str | None, optional): The value of the DNS record. Defaults to None.
        Returns:
            str | None: The ID of the DNS record if found, otherwise None.
        """
        request = requests.get(
            f"""https://api.cloudflare.com/client/v4
            /zones/{self.zone_id}
            /dns_records?name={self.table.beautify_domain_name(name) + '.frii.site'}""",

            headers={
                "Authorization": f"Bearer {self.key}",
                "X-Auth-Email": self.email
            }
        )

        # id is always string or none
        return request.json().get("result",[{}])[0].get("id") # type: ignore[no-any-return]
    
    def get_domain_attributes(self, raw_domain:str) -> dict:
        request = requests.get(
            f"""https://api.cloudflare.com/client/v4
            /zones/{self.zone_id}
            /dns_records?name={raw_domain + '.frii.site'}""",
            headers={
                    "Authorization": f"Bearer {self.key}",
                    "X-Auth-Email": self.email
               }
        ) 
        return request.json()
         


    def modify_domain(self, domain_id:str, content:str, type:str, domain:str) -> str:
        """
        Modifies a DNS record for a given domain.
        Args:
            domain_id (str): The ID of the DNS record to modify.
            content (str): The new content for the DNS record.
            type (str): The type of DNS record (e.g., A, CNAME, TXT, NS).
            domain (str): The domain name for the DNS record.
            comment (str): A comment for the DNS record. Used for administrative tasks
        Returns:
            str: The ID of the modified DNS record.
        Raises:
            DNSException: If the request to modify the DNS record fails.
            ValueError: If the ID of the modified DNS record cannot be retrieved.
        """
        request = requests.patch(
            f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records/{domain_id}",

            data=json.dumps({
                "content": content,
                "name": domain,
                "proxied": False,
                "type": type
            }),
            headers={
                "Content-Type":"application/json",
                "Authorization": f"Bearer {self.key}",
                "X-Auth-Email": self.email
            }
        )

        if not request.ok:
            raise DNSException("Failed to modify domain", request.json())
        
        id:str | None = request.json().get("result",{}).get("id")

        if id is None:
            raise ValueError("Failed to get id")

        return id # type: ignore[no-any-return]
    
    
    def register_domain(self, name:str, content:str, type:str, comment:str) -> str:
        """
        Registers a new DNS record for the specified domain.
        Args:
            name (str): The name of the DNS record. NOTE: Must use the normal DNS schema (aka a.b, NOT a[dot]b)
            content (str): The content of the DNS record.
            type (str): The type of the DNS record (e.g., A, AAAA, CNAME, etc.).
            comment (str): A comment for the DNS record.
        Returns:
            str: The ID of the newly created DNS record.
        Raises:
            DNSException: If the request to register the domain fails.
            ValueError: If the ID of the newly created DNS record cannot be retrieved.
        """
        request = requests.post(
            f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records",

            data=json.dumps({
                "content": content,
                "name": name,
                "proxied": False,
                "type": type,
            }),
            headers={
                "Content-Type":"application/json",
                "Authorization": f"Bearer {self.key}",
                "X-Auth-Email": self.email
            }
        )

        if not request.ok:
            raise DNSException("Failed to register domain",request.json())
        
        id:str | None = request.json().get("result",{}).get("id")

        if id is None:
            raise ValueError("Failed to get id")
        
        return id


    def delete_domain(self,domain_id:str) -> bool:
        """
        Deletes a DNS record for the specified domain ID.
        Args:
            domain_id (str): The ID of the domain to be deleted.
        Returns:
            bool: True if the domain was successfully deleted, False otherwise.
        """
        request = requests.delete(
            f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records/{domain_id}",

            headers={
                "Authorization": f"Bearer {self.key}",
                "X-Auth-Email": self.email
            }
        )

        if not request.ok:
            return False
        
        return True
    

    def fix_domains(self,repair_status:RepairFormat, user_id:str) -> None:
        for key, val in repair_status["broken-id"].items():
            name: str = key
            value: DomainFormat = val

            id:str | None = self.get_id(name,value["type"], value["ip"])

            id = id or self.register_domain(name,value["ip"],value["type"],f"Fixed domain for user {user_id}")
                
            self.table.modify_document(
                {f"domains.{name}":{"$exists":True}},
                operation="$set",
                key=f"domains.{name}.id",
                value=id
            )


            