import os
from dotenv import load_dotenv

load_dotenv()
os.environ["ZONE_ID"] = os.environ.get("ZONEID") or os.environ.get("ZONE_ID")

from server.main import app