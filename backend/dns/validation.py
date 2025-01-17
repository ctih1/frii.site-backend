from typing import List, Dict
from typing import TYPE_CHECKING
import string
import re
from database.tables.domains import Domains, DomainFormat
from database.tables.general import UserType
from database.exceptions import UserNotExistError
from dns.exceptions import DNSException

if TYPE_CHECKING:
    from dns.dns import DNS


ALLOWED_TYPES: List[str] = ["A","CNAME","TXT","NS"]

class Validation:
    def __init__(self, table: Domains, dns:'DNS'):
        self.dns = dns
        self.table = table

    @staticmethod
    def record_name_valid(name:str) -> bool:
        allowed:List[str] = list(string.ascii_letters)

        allowed.extend(list(string.digits))
        allowed.extend([".","-"])

        valid:bool = all(char in allowed for char in name)
        return valid
    
    def is_free(self, name:str, type:str, domains:Dict[str,DomainFormat]):
        cleaned_domain:str = Domains.clean_domain_name(name)
        if not Validation.record_name_valid(name):
            raise ValueError("Invalid record name!")
        
        if type.upper() not in ALLOWED_TYPES:
            raise DNSException(f"Type {type} is not a valid DNS record type")
        
        if cleaned_domain in domains:
            return False
        
        domain_data:dict = self.dns.get_domain_attributes(name)

        if len(domain_data.get("result",[])) == 0:
            return True
        
        else:
            REGEX_MATCH_STRING:str = r"\b[a-fA-F0-9]{64}\b"

            domain_comment:str = domain_data.get("result")[0]["comment"]
            regex_matches:List[str] = re.findall(REGEX_MATCH_STRING, domain_comment)

            username:str = regex_matches[0]

            user_data: UserType | None = self.table.find_item({"_id":username})
            
            if user_data is None or cleaned_domain not in user_data["domains"]:
                # Since the target user doesn't exist, or doesn't own the domain, it is no longer taken
                return True 

            return False




        
        
