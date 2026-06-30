# =============================================================================
# TrustShield AI -- Async MongoDB Database Layer
# =============================================================================
import os
import sys
import certifi
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()

client: AsyncIOMotorClient | None = None
db = None

# NOTE: an IPv4-only getaddrinfo monkeypatch used to live here. Removed --
# isolated testing confirmed raw TLS, pymongo, and motor all connect fine
# over this network's native IPv6/NAT64 path. The patch forced AF_INET-only
# DNS resolution on a network with no real IPv4 route, causing silent
# hangs/timeouts instead of fixing anything.


async def connect_db() -> None:
    global client, db

    mongo_uri: str = os.environ.get("MONGO_URI", "")
    db_name: str = os.environ.get("DB_NAME", "trustshield_db")

    if not mongo_uri:
        print(
            "[TrustShield] FATAL: MONGO_URI is not set in your .env file.\n"
            "              Add a line like: MONGO_URI=mongodb+srv://user:pass@cluster.../"
        )
        sys.exit(1)

    client = AsyncIOMotorClient(
        mongo_uri,
        tlsCAFile=certifi.where(),
        tlsDisableOCSPEndpointCheck=True,
        serverSelectionTimeoutMS=20000,
    )
    db = client[db_name]

    try:
        await client.admin.command("ping")
    except Exception as e:
        print(
            "[TrustShield] FATAL: Could not reach MongoDB Atlas.\n"
            f"              {type(e).__name__}: {e}\n\n"
            "              Common causes:\n"
            "              1. Atlas free-tier (M0) cluster is paused -> resume it at cloud.mongodb.com\n"
            "              2. Your current IP isn't in Atlas Network Access -> add it (or 0.0.0.0/0 for dev)\n"
            "              3. Wrong username/password in MONGO_URI\n"
            "              4. OCSP revocation check failing over IPv6/NAT64 networks ->\n"
            "                 already mitigated via tlsDisableOCSPEndpointCheck, contact maintainer if still failing\n"
        )
        sys.exit(1)

    print(f"[TrustShield] Connected to MongoDB -> {db_name}")


async def close_db() -> None:
    global client
    if client is not None:
        client.close()
        print("[TrustShield] MongoDB connection closed.")


def get_database():
    return db