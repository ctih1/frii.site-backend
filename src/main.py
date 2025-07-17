import os
from dotenv import load_dotenv
import sys
import time

load_dotenv()
os.environ["ZONE_ID"] = os.environ.get("ZONEID") or os.environ.get("ZONE_ID") or "None"

start = time.time()
from server.main import app

os.environ["start-elapsed"] = str(round(time.time() - start, 2))
os.environ["started-at"] = str(start)


if "run" in sys.argv:
    os.environ["debug"] = "True"
    import uvicorn  # type: ignore

    uvicorn.run(app)
