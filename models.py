# =============================================================================
# TrustShield AI — Pydantic v2 Data Models
# =============================================================================
#
# Pydantic models serve two purposes in FastAPI:
#   1. **Request Validation** — incoming JSON is parsed & validated at the
#      framework level before your route handler even executes.
#   2. **Response Serialization** — outgoing data is coerced to the declared
#      schema, ensuring a consistent API contract.
#
# ─── Joy of Computing: Dictionaries & Validation ────────────────────────
#
#   Under the hood, a Pydantic model instance stores its fields in a dict
#   (model.__dict__).  When you call model.model_dump(), Pydantic iterates
#   that dict and builds a *new* dict with validated/serialized values.
#
#   Think of it as a "smart dict" — it acts like a Python dictionary but
#   raises ValidationError when you put the wrong type of value in.
#
# ─── Contrast with Modern C++ ───────────────────────────────────────────
#
#   C++ enforces types at *compile time*.  A struct like:
#       struct TextRequest { std::string text; };
#   will never accept an int for `text` because the compiler rejects it.
#
#   Python is dynamically typed, so Pydantic fills the gap at *runtime*.
#   The trade-off: C++ catches errors earlier (compile vs. run), but
#   Python + Pydantic gives you richer runtime introspection (JSON Schema
#   generation, automatic Swagger docs, custom validators).
#
# =============================================================================

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# REQUEST MODELS — define what the client sends TO the server.
# ---------------------------------------------------------------------------

class TextAnalysisRequest(BaseModel):
    """
    Schema for POST /analyze/text.

    Fields:
        text (str): The raw text to analyze for potential fraud indicators.

    Pydantic will reject the request with a 422 Unprocessable Entity if
    the JSON body is missing the `text` key or its value isn't a string.
    This is analogous to a C++ function signature enforcing parameter types
    at compile time — except here it happens at HTTP-request time.
    """
    text: str = Field(
        ...,                              # `...` means "required" in Pydantic
        min_length=1,                     # must not be empty
        description="The text content to analyze for fraud indicators."
    )


class UrlAnalysisRequest(BaseModel):
    """
    Schema for POST /analyze/url.

    Fields:
        url (str): The raw URL string to analyze.

    ─── Why NOT Pydantic's HttpUrl ─────────────────────────────────────
    Pydantic's HttpUrl type validates the domain against strict IDNA
    (internationalized-domain) rules using pydantic-core's Rust `url`
    crate. That's exactly wrong for a phishing detector: attackers
    deliberately craft punycode labels (e.g. "xn--paypa1-h3a.com") that
    are syntactically punycode-shaped but do NOT decode to a legal IDNA
    label. HttpUrl rejects those with a 422 before our analysis code
    ever runs -- silently blinding the tool to the exact homograph and
    malformed-punycode attacks it exists to catch.

    Instead we accept any non-empty string here and let
    services/url_service.py do lenient, fraud-analysis-aware parsing
    (it already has an `is_valid: False` fallback path for URLs that
    can't be parsed at all, and treats that as a signal, not an error).
    """
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="The URL to analyze for phishing or fraud (any string; malformed URLs are treated as a fraud signal, not rejected)."
    )

    @field_validator("url")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be blank")
        return v


# ---------------------------------------------------------------------------
# RESPONSE MODELS — define what the server sends BACK to the client.
# ---------------------------------------------------------------------------

class AnalysisResponse(BaseModel):
    """
    Unified response for all /analyze/* endpoints.

    Fields:
        id           — MongoDB document _id as a string.
        input_type   — "text", "url", or "image".
        risk_score   — Float 0.0 (safe) to 1.0 (fraudulent).
        verdict      — Human-readable label.
        details      — Free-form dictionary with analysis metadata.
        analyzed_at  — ISO 8601 timestamp.

    The `details` field is typed as dict — Python's built-in hash table.
    In C++ you'd use std::unordered_map<std::string, std::any> for a
    similarly flexible key-value store, though you'd lose type safety.
    """
    id: str = Field(
        ...,
        description="Unique identifier for this analysis record."
    )
    input_type: str = Field(
        ...,
        description="Type of input analyzed: 'text', 'url', or 'image'."
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Fraud risk score from 0.0 (safe) to 1.0 (fraudulent)."
    )
    verdict: str = Field(
        ...,
        description="Human-readable verdict: 'safe', 'suspicious', or 'fraudulent'."
    )
    details: dict = Field(
        default_factory=dict,
        description="Additional analysis metadata as key-value pairs."
    )
    analyzed_at: datetime = Field(
        ...,
        description="UTC timestamp of when the analysis was performed."
    )


class HistoryResponse(BaseModel):
    """
    Response for GET /history.

    Wraps a list of AnalysisResponse objects with a count for convenience.

    The `analyses` field is a Python list — internally a dynamic array
    (like std::vector in C++).  It doubles its capacity when full,
    giving amortized O(1) appends.  Unlike std::vector, Python lists
    store *pointers* to objects (PyObject*), not the objects themselves,
    so there's an extra level of indirection.
    """
    analyses: list[AnalysisResponse] = Field(
        default_factory=list,
        description="List of past analysis records."
    )
    count: int = Field(
        ...,
        description="Total number of records returned."
    )
