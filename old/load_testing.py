import requests
import logging
import time
from dotenv import load_dotenv
import os
load_dotenv()

logging.warning("Starting load testing.. Please make sure the server is running on localhost:5000")

def get(path:str) -> int:
    start = time.time()
    requests.get(f"localhost:5000/{path}",headers={"X-Auth-Token":os.getenv("TESTING_ACCOUNT")})
    return time.time()-start


    