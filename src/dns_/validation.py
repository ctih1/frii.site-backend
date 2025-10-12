from typing import List, Dict, NamedTuple, Literal
from typing import TYPE_CHECKING
import logging
import string
import re
from database.tables.domains import Domains, DomainFormat
from database.tables.users import UserType
from database.exceptions import UserNotExistError, SubdomainError
from dns_.exceptions import DNSException, DomainExistsError

if TYPE_CHECKING:
    from dns_.dns import DNS

logger: logging.Logger = logging.getLogger("frii.site")

ALLOWED_TYPES: List[str] = ["A", "AAAA", "CNAME", "TXT", "NS"]


UserCanRegisterResult = NamedTuple(
    "UserCanRegisterResult", [("success", bool), ("comment", str)]
)


class Validation:
    def __init__(self, table: Domains, dns: "DNS"):
        self.dns = dns
        self.table = table

    @staticmethod
    def record_name_valid(name: str, type: str) -> bool:
        always_allowed: List[str] = list(string.ascii_letters)

        always_allowed.extend(list(string.digits))
        allowed = always_allowed.copy()
        allowed.extend([".", "-"])

        if type.upper() == "TXT":
            allowed.append("_")

        valid: bool = all(char in allowed for char in name)
        if type.upper() != "TXT" and (
            name[0] not in always_allowed or name[-1] not in always_allowed
        ):
            valid = False
        return valid

    @staticmethod
    def record_value_valid(value: str, type: str) -> bool:
        if type.upper() == "TXT":
            return True
        if type.upper() in ["CNAME", "NS"]:
            return Validation.record_name_valid(value, type)
        if type.upper() == "A":
            allowed: List[str] = list(string.digits)
            allowed.append(".")

            return all(char in allowed for char in value)

        if type.upper() == "AAAA":
            ipv6_pattern = re.compile(
                r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
            )
            return re.match(string=value, pattern=ipv6_pattern) is not None
        else:  # If type is not in checks
            logger.error(f"Type {type} is not valid!")
            return False

    def is_free(
        self,
        name: str,
        type: str,
        domains: Dict[str, DomainFormat],
        raise_exceptions: bool = True,
    ):
        """
        Checks if a given domain name is free for registration.
        Args:
            name (str): The domain to check.
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

        cleaned_domain: str = Domains.clean_domain_name(name)

        if not Validation.record_name_valid(name, type):
            logger.info(f"{name} Name is not valid")
            if raise_exceptions:
                raise ValueError(f"Invalid record name '{name}'")
            return False

        if type.upper() not in ALLOWED_TYPES:
            logger.info(f"{type} is not a valid type")

            if raise_exceptions:
                raise DNSException(f"Invalid type '{type}'", type_=type)
            return False

        if cleaned_domain in domains:
            logger.info(f"User already owns domain {cleaned_domain}")
            return False

        (domain, tld) = Domains.seperate_domain_into_parts(name)
        domain = Domains.clean_domain_name(domain)
        logger.info(f"Checking if {domain} is subdomain")

        domain_parts: List[str] = domain.split("[dot]")
        is_subdomain: bool = len(domain_parts) > 1

        required_domain: str = (
            domain_parts[-1] + "[dot]" + Domains.clean_domain_name(tld)
        )

        if required_domain and is_subdomain and required_domain not in domains:
            logger.warning(f"User does not own {required_domain}")
            if raise_exceptions:
                raise SubdomainError(
                    f"User doesn't own '{required_domain}'", required_domain
                )
            return False

        if (
            len(
                self.table.find_item({f"domains.{cleaned_domain}": {"$exists": True}})
                or []
            )
            != 0
        ):
            logger.warning(f"Domain {cleaned_domain} already exists in database")

            if raise_exceptions:
                raise DomainExistsError("Domain is already registered")
            return False

        logger.info("Domain not found in database.")

        return True

    def user_owns_domain(
        self, user_id: str, domain: str, user: UserType | None = None
    ) -> bool:
        if not user:
            user_data: UserType | None = self.table.find_user({"_id": user_id})
        else:
            user_data = user
        if user_data is None:
            raise UserNotExistError("User does not exist!")

        return (
            user_data["domains"].get(self.table.clean_domain_name(domain)) is not None
        )

    @staticmethod
    def can_user_register(domain: str, user: UserType) -> UserCanRegisterResult:
        """Checks whether users domain limit allows them to register a domain

        :param domain: a beautified domain, eg a.b.frii.site
        :type domain: str
        :param user: the user who is registering
        :type user: UserType
        :return: whether the user can register
        :rtype: UserCanRegisterResult
        """
        (name, _) = Domains.seperate_domain_into_parts(domain)
        is_subdomain = "." in name
        subdomain_amount: int = 0

        user_domain_amount = 0
        subdomain_amount = 0

        for domain in user["domains"].keys():
            (name, _) = Domains.seperate_domain_into_parts(domain)
            if "[dot]" in name:
                subdomain_amount += 1
            else:
                user_domain_amount += 1

        logger.info(
            f"User has {subdomain_amount} subdomains and {user_domain_amount} domains"
        )

        user_max_domains = user.get("permissions", {}).get("max-domains", 3)
        user_max_subdomains = user.get("permissions", {}).get("max-subdomains", 5)

        if not is_subdomain and user_domain_amount >= user_max_domains:
            return UserCanRegisterResult(False, "Domain limit exceeded")

        if is_subdomain:
            if subdomain_amount >= user_max_subdomains:
                return UserCanRegisterResult(False, "Subdomain limit exceeded")

        return UserCanRegisterResult(True, "")
