from typing import Dict, List
import logging
from typing_extensions import NotRequired, TypedDict
from database.tables.users import Users, UserType
from database.exceptions import UserNotExistError

logger: logging.Logger = logging.getLogger("frii.site")


class DomainFormat(TypedDict):
    ip: str
    registered: int | float
    type: str
    id: str


RepairFormat = TypedDict(
    "RepairFormat",
    {
        "fixed": int,
        "skipped": int,
        "duplicates": int,
        "broken-id": NotRequired[Dict[str, DomainFormat]],
    },
)


class Domains(Users):
    """Modifies domains in database.
    Please make sure to validate the domain BEFORE you use any functions here!
    """

    def __init__(self, mongo_client):
        super().__init__(mongo_client)

    @staticmethod
    def clean_domain_name(input: str) -> str:
        return input.replace(".", "[dot]")

    def beautify_domain_name(self, input: str) -> str:
        return input.replace("[dot]", ".")

    def add_domain(
        self, target_user: str, domain: str, domain_data: DomainFormat
    ) -> None:
        cleaned_domain: str = Domains.clean_domain_name(domain)

        self.modify_document(
            {"_id": target_user},
            operation="$set",
            key=f"domains.{cleaned_domain}",
            value=domain_data,
        )

    def get_domains(self, target_user: str) -> Dict[str, DomainFormat]:
        user_data: UserType | None = self.find_user({"_id": target_user})
        if user_data is None:
            raise UserNotExistError("User does not exist")
        return user_data["domains"]

    def modify_domain(
        self,
        target_user: str,
        domain: str,
        value: str | None = None,
        type: str | None = None,
    ) -> None:
        """Modifies domain in database

        Args:
            target_user (str): ID of target user
            domain (str): the record name (without .frii.site)
            value (str | None, optional): Updated record value. Defaults to current one.
            type (str | None, optional): Updated type value. Defaults to current one.

        Raises:
            ValueError: If user does not exist
        """
        cleaned_domain: str = Domains.clean_domain_name(domain)
        logger.info(f"Modifying domain {cleaned_domain}...")

        user_data: UserType | None = self.find_user({"_id": target_user})
        if user_data is None:
            raise ValueError("Failed to find user")

        domain_data: DomainFormat = user_data["domains"][cleaned_domain]

        domain_data = {
            "ip": value or domain_data["ip"],
            "registered": domain_data["registered"],
            "type": type or domain_data["type"],
            "id": domain_data["id"],
        }

        self.modify_document(
            {"_id": target_user},
            operation="$set",
            key=f"domains.{cleaned_domain}",
            value=domain_data,
        )

    def delete_domain(self, target_user: str, domain: str) -> bool:
        cleaned_domain = Domains.clean_domain_name(domain)
        logger.info(f"Deleting domain {cleaned_domain}")

        return self.remove_key({"_id": target_user}, key=f"domains.{cleaned_domain}")

    def repair_domains(self, domains: Dict[str, DomainFormat]) -> RepairFormat:
        """Repairs domains with . in their name, non destructive action"""

        updated_domains: Dict[str, DomainFormat] = {}
        fixed_domains: int = 0
        domain_offset: int = 0
        broken_id: Dict[str, DomainFormat] = {}

        for domain in domains.copy():
            domain: str = domain  # type: ignore[no-redef]
            logger.info(f"Fixing domain {domain}")

            if domain.replace(".", "[dot]") in updated_domains:
                domain_offset += 1
                continue

            if "." in domain:
                updated_domains[Domains.clean_domain_name(domain)] = domains[domain]
                fixed_domains += 1
            else:
                updated_domains[domain] = domains[domain]

            domain_id: str | None = domains[domain]["id"]

            if not domain_id:
                broken_id[Domains.clean_domain_name(domain)] = domains[domain]

        logger.info(
            f"fixed {fixed_domains}, duplicates {domain_offset}, broken ids: {len(broken_id)}"
        )
        return {
            "fixed": fixed_domains,
            "duplicates": domain_offset,
            "skipped": len(domains) - fixed_domains - domain_offset,
            "broken-id": broken_id,
        }
