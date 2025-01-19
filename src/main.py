import os
from dotenv import load_dotenv
import sys

print(os.curdir)

load_dotenv()
os.environ["ZONE_ID"] = os.environ.get("ZONEID") or os.environ.get("ZONE_ID")

from server.main import app

if "run" in sys.argv:
    import uvicorn
    uvicorn.run(app)