import os
import logging
import json
from pymongo import MongoClient
import requests # type: ignore[import-untyped]
from database.tables.domains import Domains, RepairFormat, DomainFormat
from dns_.exceptions import DNSException
from dns_.validation import Validation

logger:logging.Logger = logging.getLogger("frii.site")

class DNS:
    def __init__(self, domains:Domains):
        """Documentation for functions were created by ai.
        """
        self.table = domains
        self.key:str = os.getenv("PDNS_API_KEY") or ""

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



    def modify_domain(self, content:str, type:str, old_type:str, domain:str, user_id: str) -> bool:
        """
        Modifies a DNS record for a given domain.
        Args:
            content (str): The new content for the DNS record.
            type (str): The type of DNS record (e.g., A, CNAME, TXT, NS).
            domain (str): The domain name for the DNS record.
            user_id (str): The ID of the user registering the domain
        Returns:
            bool: if record was modified succesfully
        Raises:
            DNSException: If the request to modify the DNS record fails.
        """
        logger.debug(f"Modifying domain {domain}")
        
        if type != old_type:
            success = self.delete_domain(domain,old_type)
            if not success:
                raise DNSException({"success": success})
        
        if type == "CNAME":
            content += "."
        
        if type=="TXT":
            content = '"' + content + '"'
 
        
        logger.info(json.dumps({
                "rrsets": [{
                    "name": domain+".frii.site.",
                    "type": type,
                    "ttl": 3400,
                    "changetype": "REPLACE",
                    "records": [{
                        "content": content,
                        "disabled": False,
                        "comment": f"Modified by Session based auth ({user_id})"
                    }]
                }]
            }))
        
        request = requests.patch(
            f"https://vps.frii.site/api/v1/servers/localhost/zones/frii.site.",

            data=json.dumps({
                "rrsets": [{
                    "name": domain+".frii.site.",
                    "type": type,
                    "ttl": 3400,
                    "changetype": "REPLACE",
                    "records": [{
                        "content": content,
                        "disabled": False,
                        "comment": f"Modified by Session based auth ({user_id})"
                    }]
                }]
            }),
            headers={
                "Content-Type":"application/json",
                "X-API-Key": self.key
            }
        )

        if not request.ok:
            logger.error(f"Failed to modify domain {domain}. {request.json()}")
            raise DNSException("Failed to modify domain", request.json())

        return True


    def register_domain(self, domain:str, content:str, type:str, user_id: str) -> bool:
        """
        Registers a new DNS record for the specified domain.
        Args:
            domain (str): The name of the DNS record. NOTE: Must use the normal DNS schema (aka a.b, NOT a[dot]b)
            content (str): The content of the DNS record.
            type (str): The type of the DNS record (e.g., A, AAAA, CNAME, etc.).
            user_id (str): ID of the user creating the record
        Returns:
            str: The ID of the newly created DNS record.
        Raises:
            DNSException: If the request to register the domain fails.
            ValueError: If the ID of the newly created DNS record cannot be retrieved.
        """
        
        request = requests.patch(
            f"https://vps.frii.site/api/v1/servers/localhost/zones/frii.site.",

            data=json.dumps({
                "rrsets": [{
                    "name": domain+".frii.site.",
                    "type": type,
                    "ttl": 3400,
                    "changetype": "REPLACE",
                    "records": [{
                        "content": content,
                        "disabled": False,
                        "comment": f"Created with Session based auth ({user_id})"
                    }]
                }]
            }),
            headers={
                "Content-Type":"application/json",
                "X-API-Key": self.key
            }
        )

        if not request.ok:
            logger.error(f"Failed to register domain {domain}. {request.json()}")
            raise DNSException("Failed to register domain",request.json())

        return True


    def delete_domain(self,domain:str, type: str) -> bool:
        """
        Deletes a DNS record for the specified domain ID.
        Args:
            domain_id (str): The ID of the domain to be deleted.
        Returns:
            bool: True if the domain was successfully deleted, False otherwise.
        """
        
        logger.info(f"deleting record {domain}")
        
        request = requests.patch(
            f"https://vps.frii.site/api/v1/servers/localhost/zones/frii.site.",

            data=json.dumps({
                "rrsets": [{
                    "name": domain+".frii.site.",
                    "type": type,
                    "changetype": "DELETE",
                    "records": [{}]
                }]
            }),
            headers={
                "Content-Type":"application/json",
                "X-API-Key": self.key
            }
        )

        if not request.ok:
            logger.error(f"Could not delete domain {domain}. {request.json()}")
            return False

        return True


    def fix_domains(self,repair_status:RepairFormat, user_id:str) -> None:
        for key, val in repair_status["broken-id"].items():
            name: str = key
            value: DomainFormat = val

            logger.info(f"Trying to fix domain {name}")

            id:str | None = self.get_id(name,value["type"], value["ip"])

            logger.info("Couldn't find matching domain... Registering a new one")
            id = id or self.register_domain(name,value["ip"],value["type"],f"Fixed domain for user {user_id}")

            self.table.modify_document(
                {f"domains.{name}":{"$exists":True}},
                operation="$set",
                key=f"domains.{name}.id",
                value=id
            )


