from typing import List, Dict
import string
from database.tables.domains import Domains, DomainFormat
from dns.exceptions import DNSException
from dns.dns import DNS

ALLOWED_TYPES: List[str] = ["A","CNAME","TXT","NS"]

class Validation:
    def __init__(self, table: Domains):
        self.table = table

    @staticmethod
    def record_name_valid(name:str) -> bool:
        allowed:List[str] = list(string.ascii_letters)

        allowed.extend(list(string.digits))
        allowed.extend([".","-"])

        valid:bool = all(char in allowed for char in name)
        return valid
    
    def is_free(self, name:str, type:str, domains:Dict[str,DomainFormat]):
        if not Validation.record_name_valid(name):
            raise ValueError("Invalid record name!")
        
        if type.upper() not in ALLOWED_TYPES:
            raise DNSException(f"Type {type} is not a valid DNS record type")
        
        if Domains.clean_domain_name(name) in domains:
            return False
        

        
        
