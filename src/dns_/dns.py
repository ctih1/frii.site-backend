import os
from typing import Dict
import logging
import json
from pymongo import MongoClient
import requests  # type: ignore[import-untyped]
from database.tables.domains import Domains, RepairFormat, DomainFormat
from dns_.exceptions import DNSException
from dns_.validation import Validation

logger: logging.Logger = logging.getLogger("frii.site")


class DNS:
    def __init__(self, domains: Domains):
        """Documentation for functions were created by ai."""
        self.table = domains
        self.key: str = os.getenv("PDNS_API_KEY") or ""

    def modify_domain(
        self,
        content: str,
        type: str,
        old_type: str,
        domain: str,
        user_id: str,
        ttl: int = 240,
    ) -> bool:
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
            success = self.delete_domain(domain, old_type)
            if not success:
                raise DNSException("DNS Modification failed", json={"success": success})

        # PowerDNS will complain if these two are not present.

        if (type == "CNAME" or type == "NS") and not content.endswith("."):
            content += "."

        if type == "TXT":
            content = '"' + content + '"'

        request = requests.patch(
            f"https://vps.frii.site/api/v1/servers/localhost/zones/frii.site.",
            data=json.dumps(
                {
                    "rrsets": [
                        {
                            "name": domain + ".frii.site.",
                            "type": type,
                            "ttl": ttl,
                            "changetype": "REPLACE",
                            "records": [
                                {
                                    "content": content,
                                    "disabled": False,
                                    "comment": f"Modified by Session based auth ({user_id})",
                                }
                            ],
                        }
                    ]
                }
            ),
            headers={"Content-Type": "application/json", "X-API-Key": self.key},
        )

        if not request.ok:
            logger.error(f"Failed to modify domain {domain}. {request.json()}")
            raise DNSException("Failed to modify domain", request.json())

        return True

    def register_domain(
        self, domain: str, content: str, type: str, user_id: str
    ) -> bool:
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

        if (type == "CNAME" or type == "NS") and not content.endswith("."):
            content += "."

        if type == "TXT":
            content = '"' + content + '"'

        request = requests.patch(
            f"https://vps.frii.site/api/v1/servers/localhost/zones/frii.site.",
            data=json.dumps(
                {
                    "rrsets": [
                        {
                            "name": domain + ".frii.site.",
                            "type": type,
                            "ttl": 3400,
                            "changetype": "REPLACE",
                            "records": [
                                {
                                    "content": content,
                                    "disabled": False,
                                    "comment": f"Created with Session based auth ({user_id})",
                                }
                            ],
                        }
                    ]
                }
            ),
            headers={"Content-Type": "application/json", "X-API-Key": self.key},
        )

        if not request.ok:
            logger.error(f"Failed to register domain {domain}. {request.json()}")
            raise DNSException("Failed to register domain", request.json())

        return True

    def delete_domain(self, domain: str, type: str) -> bool:
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
            data=json.dumps(
                {
                    "rrsets": [
                        {
                            "name": domain + ".frii.site.",
                            "type": type,
                            "changetype": "DELETE",
                            "records": [{}],
                        }
                    ]
                }
            ),
            headers={"Content-Type": "application/json", "X-API-Key": self.key},
        )

        if not request.ok:
            if not self.key:
                logger.critical("DNS API key missing!")

            logger.error(f"Could not delete domain {domain}. {request.json()}")
            return False

        return True

    def delete_multiple(self, domains: Dict[str, str]):
        """Deleted multiple records at once

        Args:
            domains (Dict[str,str]): A set of keys {domain: type}
        """

        logger.info(f"mass deleting records {list(domains.keys())}")

        rrsets = [
            {"name": k, "type": v, "changetype": "DELETE", "records": [{}]}
            for k, v in domains.items()
        ]

        request = requests.patch(
            f"https://vps.frii.site/api/v1/servers/localhost/zones/frii.site.",
            data=json.dumps({"rrsets": rrsets}),
            headers={"Content-Type": "application/json", "X-API-Key": self.key},
        )

        if not request.ok:
            logger.error(
                f"Could not delete domains {list(domains.keys())}. {request.json()}"
            )
            return False

        return True
