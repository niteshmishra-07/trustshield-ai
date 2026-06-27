# =============================================================================
# TrustShield AI — FastAPI Application Entry Point
# =============================================================================
#
# This is the main module that assembles the FastAPI application:
#   1. Configures the app with a lifespan manager (startup/shutdown hooks).
#   2. Adds CORSMiddleware for cross-origin requests.
#   3. Includes routers for /analyze/* and /history endpoints.
#   4. Defines a root health-check endpoint.
#
# Run with:
#   uvicorn main:app --reload --host 0.0.0.0 --port 8000
#
# ─── Joy of Computing: The Application as a Dictionary of Routes ─────────
#
#   Internally, FastAPI (built on Starlette) maintains a routing table —
#   essentially a list of (path_pattern, http_method, handler_function)
#   tuples.  When a request arrives, the ASGI server (uvicorn) passes it
#   to FastAPI, which iterates the routing table to find a match.
#
#   The match process is NOT a simple dict lookup (because paths can have
#   parameters like /items/{id}), but for static paths it's very fast.
#
# ─── Contrast with Modern C++ ───────────────────────────────────────────
#
#   In C++ frameworks like Crow or Drogon, routes are registered at
#   compile time with template metaprogramming:
#       CROW_ROUTE(app, "/analyze/text").methods("POST"_method)(handler);
#   The compiler can optimize the routing table into a trie or hash map.
#   Python's dynamic registration is more flexible (add routes at runtime)
#   but pays a small runtime cost for the indirection.
#
# =============================================================================

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import our database lifecycle functions and route modules.
from database import connect_db, close_db
from routes.analyze import router as analyze_router
from routes.history import router as history_router


# ---------------------------------------------------------------------------
# LIFESPAN — manages startup and shutdown events.
#
# FastAPI's lifespan context manager replaces the older @app.on_event()
# pattern.  It uses Python's async context manager protocol:
#   • Code before `yield` runs at startup.
#   • Code after `yield` runs at shutdown.
#
# This is conceptually similar to C++ RAII:
#   class AppLifecycle {
#       AppLifecycle()  { connect_db(); }   // constructor = startup
#       ~AppLifecycle() { close_db(); }     // destructor = shutdown
#   };
# The key difference: Python's yield-based approach is cooperative
# (the event loop manages the lifecycle), while C++ RAII is deterministic
# (the destructor runs exactly when the object goes out of scope).
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Async context manager for application lifecycle.

    Startup:
        - Connects to MongoDB via the motor async driver.
    Shutdown:
        - Closes the MongoDB connection and releases pooled sockets.
    """
    # ── STARTUP ──
    await connect_db()
    print("[TrustShield] Application started.")

    # Yield control to the application — it runs until shutdown is triggered.
    yield

    # ── SHUTDOWN ──
    await close_db()
    print("[TrustShield] Application shut down.")


# ---------------------------------------------------------------------------
# CREATE THE FASTAPI APPLICATION
# ---------------------------------------------------------------------------

app = FastAPI(
    title="TrustShield AI",
    description=(
        "Fraud detection API that analyzes text, URLs, and images "
        "for potential fraud indicators.  Prototype with stub analysis engine."
    ),
    version="0.1.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# CORS MIDDLEWARE
#
# Cross-Origin Resource Sharing allows browsers on different domains to
# call this API.  For the prototype, we allow ALL origins ("*").
#
# How middleware works in FastAPI/Starlette:
#   Each middleware wraps the application in a layer.  Incoming requests
#   pass through middleware layers top-down (onion model):
#       Request → CORS → Router → Handler → Response → CORS → Client
#
# In C++ web frameworks, middleware is often implemented as a chain of
# function objects (std::function) or template-based filter chains.
# The ownership model differs: C++ middleware typically takes handlers
# by value or shared_ptr, while Python middleware holds references.
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # allow all origins (prototype only!)
    allow_credentials=True,
    allow_methods=["*"],        # allow all HTTP methods
    allow_headers=["*"],        # allow all headers
)


# ---------------------------------------------------------------------------
# INCLUDE ROUTERS
#
# Routers are mounted onto the app, merging their route tables.
# This is like C++ namespace composition — each router adds its
# endpoints to the global routing table.
# ---------------------------------------------------------------------------

app.include_router(analyze_router)
app.include_router(history_router)


# ---------------------------------------------------------------------------
# HEALTH CHECK ENDPOINT
# ---------------------------------------------------------------------------

@app.get(
    "/",
    summary="Health check",
    description="Returns a simple JSON object confirming the service is running.",
    tags=["Health"],
)
async def health_check() -> dict:
    """
    Root endpoint — confirms the API is alive.

    Returns a dict, which FastAPI automatically serializes to JSON.
    Under the hood, FastAPI calls json.dumps() (or orjson if installed)
    on the dict, iterating its (key, value) pairs.

    In C++, returning JSON would require building a nlohmann::json object
    or a bsoncxx::document, then serializing it to a string.  Python's
    dict-to-JSON path is simpler but slightly slower due to dynamic typing.
    """
    return {
        "status": "ok",
        "service": "TrustShield AI",
        "version": "0.1.0",
        "docs": "/docs",
    }
