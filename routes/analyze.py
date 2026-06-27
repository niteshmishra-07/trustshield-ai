# =============================================================================
# TrustShield AI — Analysis Route Handlers
# =============================================================================
#
# This module defines three POST endpoints that accept different input types
# (image, text, URL), run AI-powered fraud detection analysis via Groq LLM,
# persist the result to MongoDB, and return a unified AnalysisResponse.
#
# Integration with Member 3's services:
#   - services.ocr_service.extract_text_from_image — Tesseract OCR for images
#   - services.ai_service.analyze_text — Groq LLM fraud analysis
#
# ─── Joy of Computing: Async Functions & Dictionaries ────────────────────
#
#   Every route handler below is declared with `async def`.  When FastAPI
#   receives a request, it schedules the coroutine on the event loop.
#   Inside each handler we `await` I/O operations (file reads, DB inserts).
#   During each `await`, the event loop is FREE to serve other requests —
#   this is how a single Python thread can handle thousands of concurrent
#   connections.
#
#   Dictionaries are the workhorse data structure here:
#     • The MongoDB document we insert IS a Python dict.
#     • request.headers is a dict-like multidict.
#     • The JSON body FastAPI parses becomes a dict before Pydantic validates it.
#
# ─── Contrast with Modern C++ ───────────────────────────────────────────
#
#   In C++, async I/O is typically achieved with:
#     • std::async + std::future  (thread-based, each with its own stack)
#     • Boost.Asio / C++20 coroutines (event-loop-based, closer to Python)
#
#   Memory-wise, a Python dict stores (hash, key_ptr, value_ptr) triples in
#   a contiguous array — everything is heap-allocated behind PyObject*.
#   A C++ std::unordered_map stores key-value pairs in heap-allocated
#   buckets, but the *keys and values themselves* can be stack-allocated
#   (value semantics).  This means C++ avoids pointer-chasing overhead at
#   the cost of more complex ownership rules (move semantics, copy elision).
#
# =============================================================================

import random
from datetime import datetime, timezone

from fastapi import APIRouter, UploadFile, File, HTTPException
from pymongo.errors import ServerSelectionTimeoutError

# Import our Pydantic models and database accessor
from models import TextAnalysisRequest, UrlAnalysisRequest, AnalysisResponse
from database import get_database

# ── Member 3's AI & OCR Services ────────────────────────────────────────
# These are the real fraud detection services that replace the stub engine.
from services.ocr_service import extract_text_from_image
from services.ai_service import analyze_text as ai_analyze_text

# ---------------------------------------------------------------------------
# Create an APIRouter — FastAPI's way of grouping related endpoints.
# This is similar to a C++ namespace or a Go package: it provides logical
# grouping without creating a separate application instance.
# ---------------------------------------------------------------------------
router = APIRouter(
    prefix="/analyze",     # all routes in this file start with /analyze
    tags=["Analysis"],     # groups them in the Swagger UI sidebar
)


# ---------------------------------------------------------------------------
# SCORE CONVERSION HELPERS
#
# Member 3's AI service returns trust_score (0-100, higher = safer).
# Our AnalysisResponse expects risk_score (0.0-1.0, higher = riskier).
# These helpers bridge the two formats.
# ---------------------------------------------------------------------------

def _convert_trust_to_risk(trust_score: int) -> float:
    """
    Convert trust_score (0-100, higher=safer) to risk_score (0.0-1.0, higher=riskier).

    Formula: risk_score = (100 - trust_score) / 100
    Examples:
        trust_score=95 → risk_score=0.05  (very safe)
        trust_score=50 → risk_score=0.50  (neutral)
        trust_score=10 → risk_score=0.90  (very risky)
    """
    clamped = max(0, min(100, trust_score))
    return round((100 - clamped) / 100, 4)


def _map_ai_verdict(ai_verdict: str) -> str:
    """
    Map the AI service's verdict labels to our response format.

    AI service returns: "Safe", "Suspicious", "Scam"
    Our API returns:    "safe", "suspicious", "fraudulent"
    """
    mapping = {
        "Safe": "safe",
        "Suspicious": "suspicious",
        "Scam": "fraudulent",
    }
    return mapping.get(ai_verdict, "suspicious")


# ---------------------------------------------------------------------------
# STUB ANALYSIS ENGINE (FALLBACK)
# ---------------------------------------------------------------------------

def _perform_stub_analysis(input_type: str, content_preview: str) -> dict:
    """
    Generate a mock fraud-detection result.

    This is kept as a fallback in case the AI service is unavailable.
    In normal operation, the real AI service is used instead.

    Args:
        input_type:      "text", "url", or "image"
        content_preview: A short snippet of the input for the details field.

    Returns:
        A dictionary with keys: risk_score, verdict, details.

    ─── Dictionary Comprehension Note ─────────────────────────────────
    The returned dict is built with literal syntax `{key: value, ...}`.
    Python allocates a hash table, hashes each key string, and inserts
    the pair.  Average insertion is O(1); worst-case (hash collision
    chain) is O(n) but Python's hash randomization makes this unlikely.

    In C++, you'd build a std::unordered_map<std::string, std::variant<...>>
    or use nlohmann::json for a similarly flexible structure.
    """
    # random.random() returns a float in [0.0, 1.0) — uniform distribution.
    # In C++ you'd use std::uniform_real_distribution<double>(0.0, 1.0)
    # with a std::mt19937 engine.
    risk_score: float = round(random.random(), 4)

    # Determine the human-readable verdict based on score thresholds.
    # This is a simple if-elif-else chain; in C++ you might use a
    # constexpr lookup table or a std::map<double, std::string>.
    if risk_score < 0.3:
        verdict = "safe"
    elif risk_score < 0.7:
        verdict = "suspicious"
    else:
        verdict = "fraudulent"

    # Build the details dict — extra metadata about the analysis.
    details: dict = {
        "engine": "stub-v1.0",
        "input_type": input_type,
        "content_preview": content_preview[:200],  # truncate long inputs
        "model_version": "prototype",
        "note": "This is a stub result. Replace with real ML inference.",
    }

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "details": details,
    }


# ---------------------------------------------------------------------------
# AI-POWERED ANALYSIS HELPER
#
# Wraps Member 3's AI service and converts the response to our format.
# Falls back to the stub engine if the AI service fails critically.
# ---------------------------------------------------------------------------

def _perform_ai_analysis(input_type: str, text: str, extra_details: dict | None = None) -> dict:
    """
    Run real AI fraud analysis on the given text.

    Calls Member 3's analyze_text() service, converts the response format,
    and falls back to stub analysis if the AI returns an error indicator.

    Args:
        input_type:     "text", "url", or "image"
        text:           The text to analyze (raw text, URL string, or OCR output).
        extra_details:  Optional additional metadata to merge into the details dict.

    Returns:
        A dictionary with keys: risk_score, verdict, details — matching
        the format expected by the route handlers.
    """
    # Call Member 3's AI service
    ai_result = ai_analyze_text(text)

    # Convert trust_score → risk_score
    risk_score = _convert_trust_to_risk(ai_result["trust_score"])

    # Map the AI verdict to our format
    verdict = _map_ai_verdict(ai_result["verdict"])

    # Build the details dict with AI analysis metadata
    details: dict = {
        "engine": "groq-llama-3.3-70b",
        "input_type": input_type,
        "trust_score": ai_result["trust_score"],
        "category": ai_result.get("category", "Unknown"),
        "red_flags": ai_result.get("red_flags", []),
        "explanation": ai_result.get("explanation", ""),
        "model_version": "llama-3.3-70b-versatile",
    }

    # Merge any extra details (e.g., filename, file_size for image uploads)
    if extra_details:
        details.update(extra_details)

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "details": details,
    }


# =============================================================================
# POST /analyze/text
# =============================================================================

@router.post(
    "/text",
    response_model=AnalysisResponse,
    summary="Analyze text for fraud indicators",
    description="Accepts a JSON body with a `text` field and returns an AI-powered fraud risk assessment.",
)
async def analyze_text_route(request: TextAnalysisRequest) -> AnalysisResponse:
    """
    Analyze a text string for fraud indicators using Groq AI.

    Flow:
        1. Pydantic has already validated `request.text` (non-empty string).
        2. We pass the text to Member 3's AI service for fraud analysis.
        3. The AI returns trust_score, verdict, category, red_flags, explanation.
        4. We convert trust_score → risk_score and map the verdict.
        5. We build a MongoDB document and `await` the insert.
        6. We return the AnalysisResponse.

    ─── Async Await Explained ──────────────────────────────────────────
    `await collection.insert_one(document)` does NOT block the thread.
    Internally, motor sends the insert command over a TCP socket and
    *yields control* back to the event loop.  The event loop then
    processes other pending coroutines.  When the MongoDB server replies,
    the OS signals "socket readable", and the event loop resumes THIS
    coroutine right after the await.

    In C++ with Boost.Asio, the equivalent would be:
        co_await socket.async_write(buffer, use_awaitable);
    Both use the Proactor/Reactor pattern under the hood.
    """
    # Get the database reference (a module-level singleton, see database.py).
    db = get_database()

    # Access the "analyses" collection — this is a dict-key lookup on the
    # database object, not a network call.  It's like db["analyses"] on a
    # regular dict.
    collection = db["analyses"]

    # Run AI-powered fraud analysis via Member 3's service.
    analysis_result: dict = _perform_ai_analysis("text", request.text)

    # Build the MongoDB document.  In Python, dicts are the native format
    # for MongoDB documents — motor/pymongo handle serialization to BSON.
    # In C++, you'd build a bsoncxx::document::value using the builder API.
    document: dict = {
        "input_type": "text",
        "input_data": request.text,
        "risk_score": analysis_result["risk_score"],
        "verdict": analysis_result["verdict"],
        "details": analysis_result["details"],
        "analyzed_at": datetime.now(timezone.utc),
    }

    # Insert into MongoDB — this is the async I/O operation.
    # We wrap in try/except so the API returns a clear 503 when MongoDB
    # is unreachable, rather than an opaque 500 Internal Server Error.
    try:
        result = await collection.insert_one(document)
    except ServerSelectionTimeoutError:
        raise HTTPException(
            status_code=503,
            detail="MongoDB is unavailable. Ensure mongod is running on the configured MONGO_URI.",
        )

    # result.inserted_id is a bson.ObjectId — a 12-byte unique identifier.
    # We convert it to a string for JSON serialization.
    # In C++ terms, this is like static_cast<std::string>(objectId.to_string()).
    return AnalysisResponse(
        id=str(result.inserted_id),
        input_type="text",
        risk_score=analysis_result["risk_score"],
        verdict=analysis_result["verdict"],
        details=analysis_result["details"],
        analyzed_at=document["analyzed_at"],
    )


# =============================================================================
# POST /analyze/url
# =============================================================================

@router.post(
    "/url",
    response_model=AnalysisResponse,
    summary="Analyze a URL for phishing/fraud",
    description="Accepts a JSON body with a `url` field and returns an AI-powered fraud risk assessment.",
)
async def analyze_url(request: UrlAnalysisRequest) -> AnalysisResponse:
    """
    Analyze a URL for phishing or fraud indicators using Groq AI.

    The flow mirrors analyze_text_route().  The only difference is:
      • Pydantic validates that `request.url` is a well-formed HttpUrl.
      • We convert the HttpUrl object to a plain string before storing it,
        because MongoDB's BSON format doesn't have a native URL type.
      • The AI analyzes the URL string for phishing/fraud patterns.

    ─── Python str() vs C++ .to_string() ──────────────────────────────
    `str(request.url)` calls the __str__ dunder method on the HttpUrl
    object, which returns a new string.  In C++, you'd call .to_string()
    or use a stream insertion operator:
        std::ostringstream oss;
        oss << url;
        auto url_str = oss.str();  // allocates on the heap
    Python's str() also allocates a new string object on the heap,
    managed by reference counting + cyclic GC.
    """
    db = get_database()
    collection = db["analyses"]

    # Convert Pydantic HttpUrl to plain string for storage & preview.
    url_string: str = str(request.url)

    # Run AI-powered fraud analysis on the URL string.
    analysis_result: dict = _perform_ai_analysis("url", url_string)

    document: dict = {
        "input_type": "url",
        "input_data": url_string,
        "risk_score": analysis_result["risk_score"],
        "verdict": analysis_result["verdict"],
        "details": analysis_result["details"],
        "analyzed_at": datetime.now(timezone.utc),
    }

    try:
        result = await collection.insert_one(document)
    except ServerSelectionTimeoutError:
        raise HTTPException(
            status_code=503,
            detail="MongoDB is unavailable. Ensure mongod is running on the configured MONGO_URI.",
        )

    return AnalysisResponse(
        id=str(result.inserted_id),
        input_type="url",
        risk_score=analysis_result["risk_score"],
        verdict=analysis_result["verdict"],
        details=analysis_result["details"],
        analyzed_at=document["analyzed_at"],
    )


# =============================================================================
# POST /analyze/image
# =============================================================================

@router.post(
    "/image",
    response_model=AnalysisResponse,
    summary="Analyze an uploaded image for fraud indicators",
    description="Accepts a multipart file upload (image/*), extracts text via OCR, and returns an AI-powered fraud risk assessment.",
)
async def analyze_image(
    file: UploadFile = File(..., description="An image file to analyze.")
) -> AnalysisResponse:
    """
    Analyze an uploaded image for fraud indicators using OCR + Groq AI.

    Key differences from the text/url handlers:
      • Input comes as multipart/form-data, not JSON.
      • FastAPI wraps the upload in an UploadFile object that provides
        async file I/O methods.
      • We read the raw bytes with `await file.read()`.
      • OCR extracts text from the image via Member 3's ocr_service.
      • The extracted text is then analyzed by the AI service.

    ─── await file.read() — What Happens Under the Hood ───────────────
    UploadFile.read() is a coroutine.  When we `await` it:
      1. FastAPI reads chunks from the incoming HTTP stream.
      2. If the file is small (<1 MB), it's kept in a SpooledTemporaryFile
         in memory.  If larger, it spills to disk.
      3. The await suspends this coroutine while I/O completes, freeing
         the event loop to handle other requests.
      4. The returned `bytes` object is a contiguous block of memory.

    In C++ with an HTTP library like Crow or Drogon, you'd read into a
    std::vector<uint8_t> or std::string.  The key difference:
      • Python `bytes` is immutable and reference-counted.
      • C++ std::vector<uint8_t> is mutable and uses RAII; when it goes
        out of scope, the destructor frees the buffer deterministically.
      • Python's buffer *may* linger until the garbage collector runs.
    """
    # Validate MIME type — only accept images.
    # file.content_type is a string like "image/png" or "image/jpeg".
    # We check the prefix.  In a C++ server you'd use a similar string
    # comparison: content_type.starts_with("image/") (C++20).
    if file.content_type is None or not file.content_type.startswith("image/"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type: '{file.content_type}'. Only image files are accepted.",
        )

    # Read the file bytes asynchronously.
    contents: bytes = await file.read()
    file_size: int = len(contents)  # len() on bytes is O(1) — stored as ob_size.

    db = get_database()
    collection = db["analyses"]

    # ── OCR: Extract text from the image using Member 3's service ────
    try:
        extracted_text = extract_text_from_image(contents)
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"OCR failed to extract text from image: {str(e)}. Ensure Tesseract is installed.",
        )

    # If OCR extracted no text, return a specific message
    if not extracted_text:
        extracted_text = "(No text detected in image)"

    # ── AI Analysis: Analyze the extracted text for fraud ─────────────
    extra_details = {
        "filename": file.filename,
        "content_type": file.content_type,
        "file_size_bytes": file_size,
        "extracted_text_preview": extracted_text[:500],
    }
    analysis_result: dict = _perform_ai_analysis("image", extracted_text, extra_details)

    document: dict = {
        "input_type": "image",
        "input_data": f"image:{file.filename} ({file_size} bytes)",
        "risk_score": analysis_result["risk_score"],
        "verdict": analysis_result["verdict"],
        "details": analysis_result["details"],
        "analyzed_at": datetime.now(timezone.utc),
    }

    # ─── Dict Unpacking (**) Explained ───────────────────────────────
    # `{**dict_a, "key": value}` creates a NEW dict by copying all items
    # from dict_a and then adding/overriding with the literal entries.
    # Under the hood Python calls dict.update() on a fresh dict.
    #
    # In C++, the closest equivalent is:
    #     auto merged = base_map;              // copy
    #     merged["filename"] = filename;       // insert/overwrite
    #     merged["content_type"] = ct;
    # Or with C++17 std::merge on sorted containers.

    try:
        result = await collection.insert_one(document)
    except ServerSelectionTimeoutError:
        raise HTTPException(
            status_code=503,
            detail="MongoDB is unavailable. Ensure mongod is running on the configured MONGO_URI.",
        )

    return AnalysisResponse(
        id=str(result.inserted_id),
        input_type="image",
        risk_score=analysis_result["risk_score"],
        verdict=analysis_result["verdict"],
        details=analysis_result["details"],
        analyzed_at=document["analyzed_at"],
    )
