# =============================================================================
# TrustShield AI -- Setup Verification Script
# =============================================================================
#
# Run this BEFORE starting uvicorn to catch config problems early:
#
#   py -3.11 verify_setup.py
#
# Checks, in order:
#   1. Python version (3.11.x recommended; 3.13/3.14 are known to cause
#      issues with some native dependencies and Atlas's TLS handshake).
#   2. Required .env variables are present.
#   3. MongoDB Atlas is reachable (with the same TLS fix used in the app).
#   4. Groq API key is valid (lightweight call).
#   5. Tesseract OCR binary is discoverable.
# =============================================================================

import asyncio
import os
import shutil
import sys

from dotenv import load_dotenv

load_dotenv()


def check_python_version() -> bool:
    major, minor = sys.version_info.major, sys.version_info.minor
    print(f"Python version: {sys.version.split()[0]}")
    if (major, minor) != (3, 11):
        print(
            f"  WARNING: You're running Python {major}.{minor}. "
            "This project is built and tested against Python 3.11.\n"
            "  Run with: py -3.11 -m uvicorn main:app --reload"
        )
        return False
    print("  OK")
    return True


import socket  # noqa: F401  (kept import for any future use, patch removed below)

# NOTE: an IPv4-only getaddrinfo monkeypatch used to live here. Removed --
# it was global, so it also silently broke the Groq HTTPS check below, not
# just Mongo. Isolated testing confirmed raw TLS, pymongo, and motor all
# connect fine over this network's native IPv6/NAT64 path without it.


def check_env_vars() -> bool:
    required = ["MONGO_URI", "DB_NAME", "GROQ_API_KEY"]
    ok = True
    for var in required:
        val = os.environ.get(var)
        if not val:
            print(f"  MISSING: {var} is not set in .env")
            ok = False
        else:
            preview = val[:20] + "..." if len(val) > 20 else val
            print(f"  OK: {var} = {preview}")
    return ok


async def check_mongo() -> bool:
    try:
        import certifi
        from motor.motor_asyncio import AsyncIOMotorClient

        uri = os.environ.get("MONGO_URI", "")
        db_name = os.environ.get("DB_NAME", "trustshield_db")
        if not uri:
            print("  SKIPPED: MONGO_URI not set")
            return False

        client = AsyncIOMotorClient(
            uri,
            tlsCAFile=certifi.where(),
            tlsDisableOCSPEndpointCheck=True,
            serverSelectionTimeoutMS=20000,
        )
        await client.admin.command("ping")
        db = client[db_name]
        result = await db["analyses"].insert_one({"_verify_setup_test": True})
        await db["analyses"].delete_one({"_id": result.inserted_id})
        client.close()
        print(f"  OK: connected and wrote to '{db_name}'")
        return True
    except Exception as e:
        print(f"  FAILED: {type(e).__name__}: {e}")
        print(
            "  Most likely cause: Atlas cluster is paused (check cloud.mongodb.com)\n"
            "  or your IP isn't in Atlas Network Access."
        )
        return False


def check_groq() -> bool:
    try:
        from groq import Groq

        key = os.environ.get("GROQ_API_KEY")
        if not key:
            print("  SKIPPED: GROQ_API_KEY not set")
            return False

        client = Groq(api_key=key)
        resp = client.chat.completions.create(
            messages=[{"role": "user", "content": "Reply with just: ok"}],
            model="llama-3.3-70b-versatile",
            max_tokens=5,
        )
        print(f"  OK: Groq responded: {resp.choices[0].message.content.strip()!r}")
        return True
    except Exception as e:
        print(f"  FAILED: {type(e).__name__}: {e}")
        return False


def check_tesseract() -> bool:
    configured = os.environ.get("TESSERACT_CMD")
    detected = shutil.which("tesseract")
    path = configured or detected or r"C:\Program Files\Tesseract-OCR\tesseract.exe"

    if os.path.isfile(path) or detected:
        print(f"  OK: found at {path}")
        return True
    print(
        f"  FAILED: no Tesseract binary found (checked: {path})\n"
        "  Install from https://github.com/UB-Mannheim/tesseract/wiki\n"
        "  then set TESSERACT_CMD in .env if it's not on PATH."
    )
    return False


async def main():
    print("=" * 60)
    print("TrustShield AI -- Setup Verification")
    print("=" * 60)

    results = {}

    print("\n[1/5] Python version")
    results["python"] = check_python_version()

    print("\n[2/5] Environment variables")
    results["env"] = check_env_vars()

    print("\n[3/5] MongoDB Atlas connection")
    results["mongo"] = await check_mongo()

    print("\n[4/5] Groq API")
    results["groq"] = check_groq()

    print("\n[5/5] Tesseract OCR")
    results["tesseract"] = check_tesseract()

    print("\n" + "=" * 60)
    if all(results.values()):
        print("ALL CHECKS PASSED -- safe to run: uvicorn main:app --reload")
    else:
        failed = [k for k, v in results.items() if not v]
        print(f"FAILED CHECKS: {', '.join(failed)}")
        print("Fix these before starting the server.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())