from locust import FastHttpUser, task
import random
import string
from dotenv import load_dotenv
import os

load_dotenv()


class DomainUser(FastHttpUser):
    connection_timeout = 15.0
    network_timeout = 15.0

    @task
    def modify_domain(self):

        domain = "".join([random.choice(list(string.ascii_letters)) for _ in range(5)])
        self.client.patch(
            "/domain/modify",
            json={
                "domain": "testing-locust",
                "value": f"{domain}.cname.com",
                "type": "CNAME",
            },
            headers={"X-Auth-Token": os.getenv("TESTING_ACCOUNT")},
        )
