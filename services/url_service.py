# =============================================================================
# TrustShield AI — URL Analysis Service (Member 4)
# =============================================================================
#
# This module performs structural analysis on a URL string before it is
# sent to the Groq AI.  The idea is to catch obvious red flags using
# pattern-matching (fast, no API cost) and then pass a richer context
# string to the LLM so it can make a better decision.
#
# Flow:
#   url_string
#       │
#       ├── parse_url()          → extract scheme, domain, path, TLD
#       ├── check_suspicious_patterns()  → flag-by-flag pattern checks
#       ├── unshorten_url()      → follow redirects to reveal real destination
#       └── build_analysis_summary()     → produce text summary for AI prompt
#
# Dependencies:
#   - tldextract  : cleanly splits subdomain / domain / suffix
#   - requests    : follows HTTP redirects to unshorten URLs
#   - urllib      : built-in URL parsing (no install needed)
#
# Install:
#   pip install tldextract requests
#
# =============================================================================

import re
import urllib.parse
from typing import Optional

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    import requests as req_lib
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ---------------------------------------------------------------------------
# KNOWN SUSPICIOUS INDICATORS
# ---------------------------------------------------------------------------

# URL shorteners — these hide the real destination
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "rebrand.ly", "cutt.ly", "short.io", "is.gd",
    "rb.gy", "tiny.cc", "shorte.st", "clck.ru", "bl.ink",
}

# Suspicious top-level domains often used in phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw",
    "club", "work", "date", "faith", "racing", "win",
    "stream", "download", "click", "link", "online", "site",
}

# Keywords inside the URL path/domain that indicate phishing
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "payment", "confirm", "otp", "kyc", "aadhaar",
    "pan-card", "upi", "reward", "prize", "winner", "claim",
    "free-offer", "lucky", "congratulations", "refund",
    "support-team", "helpdesk", "customer-care",
]

# Legitimate brands that scammers impersonate — if these appear in a
# suspicious context (wrong domain, wrong TLD) it's a red flag
IMPERSONATED_BRANDS = [
    "hdfc", "sbi", "icici", "axis", "kotak",          # Banks
    "paytm", "phonepe", "gpay", "bhim",                # Payment apps
    "amazon", "flipkart", "myntra",                    # E-commerce
    "google", "microsoft", "apple",                    # Tech
    "irdai", "sebi", "rbi", "income-tax", "epfo",     # Government
    "jio", "airtel", "bsnl",                           # Telecom
    "irctc", "uidai", "nsdl",                          # Indian services
]

# Legitimate official domains for the above brands (subset)
LEGITIMATE_DOMAINS = {
    "hdfcbank.com", "sbi.co.in", "icicibank.com",
    "paytm.com", "phonepe.com", "gpay.app",
    "amazon.in", "flipkart.com",
    "google.com", "microsoft.com", "apple.com",
    "incometax.gov.in", "uidai.gov.in", "irctc.co.in",
    "jio.com", "airtel.in", "bsnl.in",
}


# ---------------------------------------------------------------------------
# CORE ANALYSIS FUNCTIONS
# ---------------------------------------------------------------------------

def parse_url(url: str) -> dict:
    """
    Parse a URL into its components.

    Returns a dict with:
        scheme    : "http" or "https" (or empty string)
        domain    : the registered domain (e.g. "hdfcbank.com")
        subdomain : everything before the domain (e.g. "secure.login")
        suffix    : the TLD (e.g. "com", "xyz")
        path      : the URL path after the domain
        full_url  : the original URL string
        is_valid  : True if the URL could be parsed at all
    """
    # Ensure scheme is present so urllib can parse it correctly
    if not url.startswith("http://") and not url.startswith("https://"):
        url_to_parse = "https://" + url
    else:
        url_to_parse = url

    try:
        parsed = urllib.parse.urlparse(url_to_parse)
    except Exception:
        return {"is_valid": False, "full_url": url}

    if TLDEXTRACT_AVAILABLE:
        ext = tldextract.extract(url_to_parse)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        subdomain = ext.subdomain
        suffix = ext.suffix
    else:
        # Fallback without tldextract
        host = parsed.netloc.split(":")[0]  # strip port
        parts = host.split(".")
        suffix = parts[-1] if len(parts) >= 1 else ""
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

    return {
        "is_valid": True,
        "full_url": url,
        "scheme": parsed.scheme,
        "domain": domain,
        "subdomain": subdomain,
        "suffix": suffix,
        "path": parsed.path + ("?" + parsed.query if parsed.query else ""),
        "netloc": parsed.netloc,
    }


def unshorten_url(url: str, timeout: int = 5) -> Optional[str]:
    """
    Follow HTTP redirects to reveal the real destination of a shortened URL.

    Args:
        url     : the short URL to unshorten
        timeout : seconds before giving up (default 5)

    Returns:
        The final resolved URL, or None if the request failed.
    """
    if not REQUESTS_AVAILABLE:
        return None

    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        resp = req_lib.head(url, allow_redirects=True, timeout=timeout)
        final_url = resp.url

        # If head() doesn't follow properly, try GET
        if final_url == url:
            resp = req_lib.get(url, allow_redirects=True, timeout=timeout, stream=True)
            final_url = resp.url

        return final_url
    except Exception:
        return None


def check_suspicious_patterns(parsed: dict) -> list[str]:
    """
    Run a battery of pattern checks against a parsed URL.

    Returns a list of red-flag strings.  Empty list means no flags found.
    """
    flags = []
    full_url_lower = parsed.get("full_url", "").lower()
    domain = parsed.get("domain", "").lower()
    subdomain = parsed.get("subdomain", "").lower()
    suffix = parsed.get("suffix", "").lower()
    path = parsed.get("path", "").lower()
    scheme = parsed.get("scheme", "").lower()

    # 1. HTTP instead of HTTPS
    if scheme == "http":
        flags.append("Uses insecure HTTP — no encryption, data can be intercepted")

    # 2. Suspicious TLD
    if suffix in SUSPICIOUS_TLDS:
        flags.append(f"Suspicious top-level domain '.{suffix}' — commonly used in scam sites")

    # 3. Is a URL shortener
    if domain in SHORTENER_DOMAINS:
        flags.append(f"URL is shortened via {domain} — real destination is hidden")

    # 4. Excessive subdomains (e.g. secure.login.verify.hdfc.xyz.com)
    subdomain_parts = [s for s in subdomain.split(".") if s]
    if len(subdomain_parts) >= 3:
        flags.append(
            f"Unusually deep subdomain structure ({subdomain}.{domain}) — "
            "legitimate sites rarely have more than 1-2 subdomain levels"
        )

    # 5. Brand name in subdomain but wrong domain (impersonation)
    for brand in IMPERSONATED_BRANDS:
        if brand in subdomain and domain not in LEGITIMATE_DOMAINS:
            flags.append(
                f"Impersonates '{brand}' in subdomain but is NOT the official domain "
                f"(actual domain: {domain})"
            )

    # 6. Suspicious keywords in the URL
    combined = domain + subdomain + path
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in combined]
    if found_keywords:
        flags.append(
            f"Suspicious keywords in URL: {', '.join(found_keywords[:4])} — "
            "often used in phishing and credential-harvesting pages"
        )

    # 7. IP address instead of domain name
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    netloc_host = parsed.get("netloc", "").split(":")[0]
    if ip_pattern.match(netloc_host):
        flags.append(
            f"URL uses a raw IP address ({netloc_host}) instead of a domain name — "
            "legitimate services always use domain names"
        )

    # 8. Very long URL (common in phishing to hide the real domain)
    if len(parsed.get("full_url", "")) > 150:
        flags.append(
            "Unusually long URL — scammers often use long URLs to bury the real domain "
            "and confuse users"
        )

    # 9. Lookalike characters in domain (e.g. rn → m, 0 → o)
    lookalike_pairs = [("rn", "m"), ("0", "o"), ("1", "l"), ("vv", "w")]
    for fake, real in lookalike_pairs:
        if fake in domain:
            flags.append(
                f"Domain '{domain}' may use lookalike character '{fake}' to impersonate "
                f"a site using '{real}' — a common visual spoofing trick"
            )

    return flags


def build_analysis_summary(url: str) -> dict:
    """
    Run the full URL analysis pipeline and return a structured result.

    This is the main function called by the backend route.

    Returns:
        {
            "original_url"   : str,
            "resolved_url"   : str | None,   # after unshortening
            "was_shortened"  : bool,
            "structural_flags": list[str],   # pattern-based red flags
            "domain"         : str,
            "scheme"         : str,
            "suffix"         : str,
            "ai_prompt_text" : str,          # enriched text to send to AI
        }
    """
    parsed = parse_url(url)

    if not parsed.get("is_valid"):
        return {
            "original_url": url,
            "resolved_url": None,
            "was_shortened": False,
            "structural_flags": ["Could not parse the URL — it may be malformed"],
            "domain": "",
            "scheme": "",
            "suffix": "",
            "ai_prompt_text": f"Analyze this URL for fraud: {url}\n(Note: URL could not be parsed)",
        }

    domain = parsed.get("domain", "")
    was_shortened = domain in SHORTENER_DOMAINS
    resolved_url = None

    # If shortened, follow redirects to find real URL
    if was_shortened:
        resolved_url = unshorten_url(url)
        if resolved_url and resolved_url != url:
            # Re-analyze the real destination
            real_parsed = parse_url(resolved_url)
            extra_flags = check_suspicious_patterns(real_parsed)
            flags = [f"URL is a shortlink — redirects to: {resolved_url}"]
            flags += extra_flags
        else:
            flags = check_suspicious_patterns(parsed)
            flags.append("Could not unshorten URL to reveal real destination")
    else:
        flags = check_suspicious_patterns(parsed)

    # Build enriched text for the AI
    ai_prompt_lines = [
        f"URL being analyzed: {url}",
    ]
    if resolved_url:
        ai_prompt_lines.append(f"Resolved (real) URL after following shortlink: {resolved_url}")
    ai_prompt_lines += [
        f"Domain: {domain}",
        f"Scheme: {parsed.get('scheme', 'unknown')}",
        f"TLD: .{parsed.get('suffix', 'unknown')}",
        f"Subdomain: {parsed.get('subdomain', 'none') or 'none'}",
        "",
        "Structural red flags detected by pattern analysis:",
    ]
    if flags:
        for flag in flags:
            ai_prompt_lines.append(f"  - {flag}")
    else:
        ai_prompt_lines.append("  (no structural red flags detected)")

    ai_prompt_lines += [
        "",
        "Based on the URL structure and the flags above, assess whether this URL is safe, suspicious, or a scam.",
    ]

    return {
        "original_url": url,
        "resolved_url": resolved_url,
        "was_shortened": was_shortened,
        "structural_flags": flags,
        "domain": domain,
        "scheme": parsed.get("scheme", ""),
        "suffix": parsed.get("suffix", ""),
        "ai_prompt_text": "\n".join(ai_prompt_lines),
    }


# ---------------------------------------------------------------------------
# QR CODE DECODING
# ---------------------------------------------------------------------------

def decode_qr_from_bytes(image_bytes: bytes) -> Optional[str]:
    """
    Decode a QR code from raw image bytes and return the embedded data.

    Requires:
        - pyzbar  : pip install pyzbar
        - Pillow  : pip install Pillow
        - On Windows: install ZBar DLLs from https://github.com/NaturalHistoryMuseum/pyzbar#windows-error

    Args:
        image_bytes : Raw bytes of the QR code image (PNG, JPEG, etc.)

    Returns:
        The decoded string (usually a URL) or None if:
            - No QR code was found in the image
            - pyzbar is not installed
            - Image could not be read
    """
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        from PIL import Image
        import io

        image = Image.open(io.BytesIO(image_bytes))
        decoded_objects = pyzbar_decode(image)

        if not decoded_objects:
            return None

        # Take the first QR code found
        raw_data = decoded_objects[0].data
        return raw_data.decode("utf-8")

    except ImportError:
        # pyzbar or Pillow not installed — return None gracefully
        return None
    except Exception:
        return None
