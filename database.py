# =============================================================================
# TrustShield AI — Async MongoDB Database Layer
# =============================================================================
#
# This module manages the lifecycle of the MongoDB connection using the
# `motor` async driver.  motor wraps PyMongo and exposes the same API but
# with coroutine-based methods, making it a perfect fit for FastAPI's async
# request handlers.
#
# ─── Joy of Computing: Async I/O in Python ──────────────────────────────
#
#   In synchronous Python (or C), a database call *blocks* the thread:
#       result = collection.find_one({"_id": id})   # thread sleeps here
#
#   In async Python we *await* instead:
#       result = await collection.find_one({"_id": id})
#
#   While waiting, Python's event loop can serve OTHER requests — this is
#   cooperative multitasking.  The key data structure is a **dictionary**
#   (hash-map) inside the event loop that maps file-descriptors to callback
#   coroutines.  When the OS signals "socket ready", the loop resumes the
#   right coroutine via that dict lookup — O(1) average time.
#
# ─── Contrast with Modern C++ ───────────────────────────────────────────
#
#   C++ achieves concurrency through std::thread or std::async, where each
#   thread has its own stack (typically 1-8 MB).  Memory ownership is
#   explicit: you'd wrap the DB handle in a std::unique_ptr or
#   std::shared_ptr so the destructor closes the connection (RAII pattern).
#
#   In Python, the motor client is reference-counted by the garbage
#   collector.  When the last reference drops, __del__ *may* close the
#   socket — but we don't rely on that.  Instead, we explicitly call
#   client.close() in the lifespan shutdown hook below, mirroring the
#   deterministic cleanup that RAII provides in C++.
#
# =============================================================================

import os
from motor.motor_asyncio import AsyncIOMotorClient  # async MongoDB driver
from dotenv import load_dotenv                       # .env file loader

# ---------------------------------------------------------------------------
# Load environment variables from the .env file at module import time.
# load_dotenv() reads key=value pairs and injects them into os.environ,
# which is itself a dict-like object (os._Environ).  This is analogous to
# reading a config file in C++ and storing values in a std::unordered_map.
# ---------------------------------------------------------------------------
load_dotenv()

# ---------------------------------------------------------------------------
# Module-level "singleton" references.
#
# In Python, module-level variables act as singletons because Python caches
# imported modules in sys.modules (a dict mapping module names → module
# objects).  Every `from database import db` across the app gets the SAME
# object.  In C++, you'd achieve this with a Meyers singleton or a
# namespace-scoped static variable.
# ---------------------------------------------------------------------------
client: AsyncIOMotorClient | None = None  # Will hold the motor client
db = None  # Will hold the database reference


async def connect_db() -> None:
    """
    Establish the MongoDB connection.

    Called once during FastAPI's lifespan startup event.

    How it works:
    1. Read MONGO_URI and DB_NAME from os.environ (populated by load_dotenv).
    2. Create an AsyncIOMotorClient — this doesn't open a socket immediately;
       motor uses a lazy connection pool that opens sockets on first I/O.
    3. Store references in module-level globals so every route handler can
       import `db` and use it directly.

    In C++ terms, this is similar to:
        auto client = std::make_unique<MongoClient>(uri);
        auto* db = client->database(db_name);
    But in C++ the unique_ptr *owns* the client and will destroy it when the
    owning scope exits, whereas here we rely on the shutdown hook below.
    """
    global client, db

    # os.environ.get() is a dictionary .get() call — returns the value for
    # the key if it exists, otherwise the default.  Under the hood Python
    # hashes the key string and probes the hash table.
    mongo_uri: str = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    db_name: str = os.environ.get("DB_NAME", "trustshield_db")

    # Create the async client.  motor internally manages a connection pool
    # (default maxPoolSize=100).  Each pool slot is a TCP socket.
    client = AsyncIOMotorClient(mongo_uri)

    # Select the database — this is a lightweight dict-key lookup inside the
    # client object; no network call happens here.
    db = client[db_name]

    print(f"[TrustShield] Connected to MongoDB -> {db_name}")


async def close_db() -> None:
    """
    Gracefully close the MongoDB connection.

    Called once during FastAPI's lifespan shutdown event.

    This is the Python equivalent of a C++ destructor / RAII cleanup:
    we explicitly release all pooled TCP sockets so the OS can reclaim
    file descriptors immediately rather than waiting for garbage collection.
    """
    global client
    if client is not None:
        client.close()
        print("[TrustShield] MongoDB connection closed.")


def get_database():
    """
    Accessor for the database instance.

    Returns the module-level `db` reference.  Every caller gets the same
    object — no copies are made because Python variables are *references*
    (pointers under the hood, similar to T* in C++), not value copies.

    In C++, returning a raw pointer to a module-static would look like:
        Database* get_database() { return db; }
    The critical difference: C++ callers must never `delete` that pointer
    (they don't own it).  In Python, ownership is managed by reference
    counting, so this isn't a concern.
    """
    return db
