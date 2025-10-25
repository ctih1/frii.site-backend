import os
from typing import Dict, List
import logging
import json
from pymongo import MongoClient
import requests  # type: ignore[import-untyped]
from database.tables.domains import Domains, RepairFormat, DomainFormat
from dns_.exceptions import DNSException
from dns_.validation import Validation

logger: logging.Logger = logging.getLogger("frii.site")


def sanitize(content: str, type: str) -> str:
    if (type == "CNAME" or type == "NS") and not content.rstrip().endswith("."):
        content += "."

    if type == "TXT" and not content.startswith('"'):
        content = '"' + content
    if type == "TXT" and not content.endswith('"'):
        content += '"'

    return content


class DNS:
    def __init__(self, domains: Domains):
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

        if type != old_type:
            success = self.delete_domain(domain, old_type)
            if not success:
                raise DNSException("DNS Modification failed", json={"success": success})

        (name, tld) = Domains.seperate_domain_into_parts(domain)

        logger.debug(f"Modifying domain {name} tld {tld}")

        # PowerDNS will complain if these two are not present.
        content = sanitize(content, type)

        request = requests.patch(
            f"https://vps.frii.site/api/v1/servers/localhost/zones/{tld}.",
            data=json.dumps(
                {
                    "rrsets": [
                        {
                            "name": name + f".{tld}.",
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

            if not self.key:
                logger.critical("API key not defined!")

            raise DNSException("Failed to modify domain", request.json())

        return True

    def register_domain(
        self, domain: str, content: str, type: str, user_id: str
    ) -> bool:
        """
        Registers a new DNS record for the specified domain.
        Args:
            domain (str): The name of the DNS record. NOTE: Must use the normal DNS schema (aka a.b.frii.site, NOT a[dot]b[dot]frii[dot]site)
            content (str): The content of the DNS record.
            type (str): The type of the DNS record (e.g., A, AAAA, CNAME, etc.).
            user_id (str): ID of the user creating the record
        Returns:
            str: The ID of the newly created DNS record.
        Raises:
            DNSException: If the request to register the domain fails.
            ValueError: If the ID of the newly created DNS record cannot be retrieved.
        """

        content = sanitize(content, type)

        (name, tld) = Domains.seperate_domain_into_parts(domain)

        request = requests.patch(
            f"https://vps.frii.site/api/v1/servers/localhost/zones/{tld}.",
            data=json.dumps(
                {
                    "rrsets": [
                        {
                            "name": name + f".{tld}.",
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

            if not self.key:
                logger.error("API key not defined!")

            raise DNSException("Failed to register domain", request.json())

        return True

    def register_multiple(self, domains: Dict[str, DomainFormat], user_id: str) -> bool:
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

        rrsets: Dict[str, List[dict]] = {}

        for domain, values in domains.items():
            (name, tld) = Domains.seperate_domain_into_parts(domain)

            values["ip"] = sanitize(values["ip"], values["type"])

            rrset = {
                "name": name + f".{tld}.",
                "type": values["type"],
                "ttl": 3400,
                "changetype": "REPLACE",
                "records": [
                    {
                        "content": values["ip"],
                        "disabled": False,
                        "comment": f"Reinstated from banned user ({user_id})",
                    }
                ],
            }

            rrsets[tld].append(rrset)

        for tld, tld_rrsets in rrsets.items():
            request = requests.patch(
                f"https://vps.frii.site/api/v1/servers/localhost/zones/{tld}.",
                data=json.dumps({"rrsets": tld_rrsets}),
                headers={"Content-Type": "application/json", "X-API-Key": self.key},
            )

            if not request.ok:
                logger.error(
                    f"Failed to register domains for TLD {tld}. {request.json()}"
                )

                if not self.key:
                    logger.critical("API key not defined!")

                raise DNSException("Failed to register domain", request.json())

        return True

    def delete_domain(self, domain: str, type: str) -> bool:
        """Deletes a domain

        :param domain: the full domain (e.g. a.b.frii.site)
        :type domain: str
        :param type: the type of the domain (e.g. A, AAAA)
        :type type: str
        :return: whether was succesfull
        :rtype: bool
        """

        (name, tld) = Domains.seperate_domain_into_parts(domain)

        logger.info(f"deleting record {domain}")

        request = requests.patch(
            f"https://vps.frii.site/api/v1/servers/localhost/zones/{tld}.",
            data=json.dumps(
                {
                    "rrsets": [
                        {
                            "name": name + f".{tld}.",
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

        rrsets: Dict[str, List[dict]] = {}

        for domain, type in domains.items():
            (name, tld) = Domains.seperate_domain_into_parts(domain)

            rrsets[tld].append(
                {
                    "name": name + f".{tld}.",
                    "type": type,
                    "changetype": "DELETE",
                    "records": [{}],
                }
            )

        for tld, tld_rrsets in rrsets.items():
            request = requests.patch(
                f"https://vps.frii.site/api/v1/servers/localhost/zones/{tld}.",
                data=json.dumps({"rrsets": tld_rrsets}),
                headers={"Content-Type": "application/json", "X-API-Key": self.key},
            )

            if not request.ok:
                logger.error(
                    f"Failed to delete domains for TLD {tld}. {request.json()}"
                )

                if not self.key:
                    logger.critical("API key not defined!")

                return False
        return True
