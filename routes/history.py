# =============================================================================
# TrustShield AI — History Route Handler
# =============================================================================
#
# This module defines the GET /history endpoint that retrieves past analysis
# records from MongoDB with pagination support.
#
# ─── Joy of Computing: Async Iteration ───────────────────────────────────
#
#   MongoDB cursors in motor support Python's `async for` protocol.
#   Instead of loading ALL documents into memory at once (dangerous for
#   large datasets), the cursor fetches them in batches from the server.
#
#   Contrast with a regular `for` loop over a list:
#     • `for doc in list_of_docs`  — all items already in memory.
#     • `async for doc in cursor`  — each batch is fetched asynchronously;
#       the event loop is free between batches.
#
# ─── Contrast with Modern C++ ───────────────────────────────────────────
#
#   C++ iterators have strict invalidation rules:
#     • Inserting into a std::vector invalidates ALL iterators.
#     • Inserting into a std::map invalidates NONE.
#   Python iterators (and async iterators) don't have invalidation in the
#   same sense — but modifying a dict during iteration raises RuntimeError.
#
#   For database cursors specifically, both Python (motor) and C++
#   (mongocxx) use server-side cursors that are independent of local
#   container mutations.
#
# =============================================================================

from fastapi import APIRouter, Query, HTTPException
from pymongo.errors import ServerSelectionTimeoutError

from models import AnalysisResponse, HistoryResponse
from database import get_database

# ---------------------------------------------------------------------------
# Router for the /history endpoint group.
# ---------------------------------------------------------------------------
router = APIRouter(
    tags=["History"],
)


@router.get(
    "/history",
    response_model=HistoryResponse,
    summary="Retrieve past analysis records",
    description="Fetches analysis history from MongoDB with pagination via `skip` and `limit`.",
)
async def get_history(
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
        description="Maximum number of records to return (1–200).",
    ),
    skip: int = Query(
        default=0,
        ge=0,
        description="Number of records to skip (for pagination).",
    ),
) -> HistoryResponse:
    """
    Fetch analysis history from MongoDB.

    Flow:
        1. Query the "analyses" collection with skip/limit pagination.
        2. Sort by `analyzed_at` descending (newest first).
        3. Iterate the async cursor and build a list of AnalysisResponse.
        4. Return wrapped in HistoryResponse.

    ─── How the Async Cursor Works ────────────────────────────────────
    `collection.find()` returns an AsyncIOMotorCursor.  It does NOT
    execute the query immediately — it's lazy (like a Python generator).
    The actual MongoDB query fires when we start iterating with
    `async for`.

    motor fetches documents in batches (default batchSize ~101 for first
    batch, then 16 MB worth).  Between batches, the coroutine awaits
    the network response, and the event loop can serve other requests.

    In C++, the mongocxx driver's cursor is a forward iterator:
        auto cursor = collection.find(filter);
        for (auto&& doc : cursor) {   // blocks the thread per batch
            process(doc);
        }
    The C++ version blocks the calling thread; to make it async you'd
    need to integrate with Boost.Asio or use a thread pool.

    ─── List Building with .append() ──────────────────────────────────
    We build the result list with `analyses.append(...)`.  Python lists
    are dynamic arrays (like std::vector).  `.append()` is amortized
    O(1) — when the internal array is full, Python allocates a new array
    ~1.125x the old size and copies pointers (not objects!).

    In C++ with std::vector, push_back() copies/moves the actual object
    (value semantics), not just a pointer.  This gives better cache
    locality but more expensive reallocation.
    """
    db = get_database()
    collection = db["analyses"]

    # Build the query cursor with sorting and pagination.
    # .sort("analyzed_at", -1)  →  descending order (newest first).
    # .skip(skip)               →  offset for pagination.
    # .limit(limit)             →  cap the number of returned documents.
    #
    # Each of these methods returns the SAME cursor object (fluent API
    # pattern, like method chaining in C++ builder patterns).
    cursor = collection.find().sort("analyzed_at", -1).skip(skip).limit(limit)

    # Accumulate results into a Python list.
    # In C++ you might do:  std::vector<AnalysisResponse> analyses;
    #                        analyses.reserve(limit);  // pre-allocate
    analyses: list[AnalysisResponse] = []

    # ─── async for ───────────────────────────────────────────────────
    # This is Python's asynchronous iteration protocol.  Under the hood:
    #   1. Python calls cursor.__aiter__() -> returns the cursor itself.
    #   2. Python calls await cursor.__anext__() -> returns next document.
    #   3. When exhausted, __anext__() raises StopAsyncIteration.
    # The `await` in step 2 is where the event loop can context-switch.
    try:
        async for document in cursor:
            # Each `document` is a Python dict returned by motor.
            # MongoDB's _id field is a bson.ObjectId, which we convert to str.
            #
            # dict.get(key, default) is O(1) average -- it hashes the key and
            # probes the hash table.  If the key is missing, it returns the
            # default instead of raising KeyError.  In C++ this is:
            #   auto it = map.find(key);
            #   auto val = (it != map.end()) ? it->second : default_val;
            analyses.append(
                AnalysisResponse(
                    id=str(document.get("_id", "")),
                    input_type=document.get("input_type", "unknown"),
                    risk_score=document.get("risk_score", 0.0),
                    verdict=document.get("verdict", "unknown"),
                    details=document.get("details", {}),
                    analyzed_at=document.get("analyzed_at"),
                )
            )
    except ServerSelectionTimeoutError:
        raise HTTPException(
            status_code=503,
            detail="MongoDB is unavailable. Ensure mongod is running on the configured MONGO_URI.",
        )

    # Return the wrapped response.
    # len() on a Python list is O(1) — the list object stores its length
    # as an internal field (ob_size), just like std::vector::size().
    return HistoryResponse(
        analyses=analyses,
        count=len(analyses),
    )
