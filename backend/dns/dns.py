import requests
import os
from database.tables.domains import Domains, RepairFormat, DomainFormat
from pymongo import MongoClient

class DNS:
    def __init__(self, mongo_client:MongoClient):
        self.table = Domains(mongo_client)
        self.zone_id:str = os.getenv("ZONE_ID") or ""
        self.key:str = os.getenv("CF_KEY_W") or ""
        self.email:str = os.getenv("EMAIL") or ""

    def get_id(self, name:str, type:str|None= None, value:str|None=None) -> str | None:
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

    def fix_domains(self,repair_status:RepairFormat) -> None:
        for key, val in repair_status["broken-id"].items():
            name: str = key
            value: DomainFormat = val

            self.get_id(name,value["type"], value["ip"])


            
            