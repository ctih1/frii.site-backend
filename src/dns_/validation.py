from typing import List, Dict
from typing import TYPE_CHECKING
import string
import re
from database.tables.domains import Domains, DomainFormat
from database.tables.users import UserType
from database.exceptions import UserNotExistError, SubdomainError
from dns_.exceptions import DNSException, DomainExistsError

if TYPE_CHECKING:
    from dns_.dns import DNS


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
    
    @staticmethod
    def record_value_valid(value:str, type:str) -> bool:
        if type.upper() == "TXT":
            return True
        if type.upper() in ["CNAME","NS"]:
            return Validation.record_name_valid(value)
        if type.upper() == "A":
            allowed:List[str] = list(string.digits)
            allowed.append(".")

        return all(char in allowed for char in value)
    
    def is_free(self, name:str, type:str, domains:Dict[str,DomainFormat], raise_exceptions:bool=True):
        """
        Checks if a given domain name is free for registration.
        Args:
            name (str): The domain name to check.
            type (str): The type of DNS record.
            domains (Dict[str, DomainFormat]): A dictionary of domains owned by the user.
            raise_exceptions (bool, optional): Whether to raise exceptions on validation errors. Defaults to True.
        Returns:
            bool: True if the domain name is free, False otherwise.
        Raises:
            ValueError: If the record name is invalid and raise_exceptions is True.
            DNSException: If the DNS record type is invalid and raise_exceptions is True.
            SubdomainError: If the user doesn't own the required domain and raise_exceptions is True.
        """

        cleaned_domain:str = Domains.clean_domain_name(name)

        if not Validation.record_name_valid(name):
            if raise_exceptions:
                raise ValueError(f"Invalid record name '{name}'")
            return False
        
        if type.upper() not in ALLOWED_TYPES:
            if raise_exceptions:
                raise DNSException(f"Invalid type '{type}'", type_=type)
            return False

        if cleaned_domain in domains:
            return False
        
        domain_parts:List[str] = cleaned_domain.split("[dot]")
        is_subdomain:bool = len(domain_parts) > 1

        required_domain:str = domain_parts[-1]

        if required_domain and is_subdomain and required_domain not in domains:
            if raise_exceptions:
                raise SubdomainError(f"User doesn't own '{required_domain}'", required_domain)
            return False
        
        if len(self.table.find_item({f"domains.{cleaned_domain}":{"$exists":True}}) or []) != 0:
            if raise_exceptions:
                raise DomainExistsError("Domain is already registered")
            return False
        
        domain_data:dict = self.dns.get_domain_attributes(name)

        if len(domain_data.get("result",[])) == 0:
            # Domain has not been registered
            return True
        
        else:
            # Check if domain holder has an account
            REGEX_MATCH_STRING:str = r"\b[a-fA-F0-9]{64}\b"

            domain_comment:str = domain_data.get("result")[0]["comment"] # type: ignore[index]
            regex_matches:List[str] = re.findall(REGEX_MATCH_STRING, domain_comment)
            username:str = regex_matches[0]

            user_data: UserType | None = self.table.find_user({"_id":username})
            
            if user_data is None or cleaned_domain not in user_data["domains"]:
                # Since the target user doesn't exist, or doesn't own the domain, it is no longer taken
                return True 

            return False


    def user_owns_domain(self,user_id:str, domain:str) -> bool:
        user_data: UserType | None = self.table.find_user({"_id":user_id})
        if user_data is None:
            raise UserNotExistError("User does not exist!")
        return user_data["domains"].get(self.table.clean_domain_name(domain)) is not None
    

        
        
