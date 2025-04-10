import os
from dotenv import load_dotenv
import sys
import time

load_dotenv()
os.environ["ZONE_ID"] = os.environ.get("ZONEID") or os.environ.get("ZONE_ID")

start = time.time()
from server.main import app
print(f"Server ready in {round(time.time() - start,2)} seconds")

if "run" in sys.argv:
    import uvicorn
    uvicorn.run(app)