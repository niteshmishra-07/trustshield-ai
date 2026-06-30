import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()
uri = os.getenv("MONGO_URI")

client = MongoClient(uri, tlsDisableOCSPEndpointCheck=True, serverSelectionTimeoutMS=8000)
print(client.admin.command("ping"))