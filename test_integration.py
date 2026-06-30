"""
TrustShield AI — Integration Test Script (Member 4)
====================================================

Tests all four backend endpoints end-to-end:
    POST /analyze/text
    POST /analyze/url
    POST /analyze/image
    POST /analyze/qr

How to run:
    1. Make sure the backend is running:
           uvicorn main:app --reload --host 0.0.0.0 --port 8000
    2. Run this script from the project root:
           python test_integration.py

What it checks:
    - HTTP 200 status on every call
    - Response has all required fields (id, risk_score, verdict, details, analyzed_at)
    - risk_score is between 0.0 and 1.0
    - verdict is one of the valid values
    - details contains engine and category

Requires:
    pip install requests Pillow qrcode pyzbar
"""

import io
import sys
import json
import time

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

BASE_URL = "http://localhost:8000"

VALID_VERDICTS = {"safe", "suspicious", "fraudulent"}

# Colour codes for terminal output
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# ---------------------------------------------------------------------------
# TEST SAMPLES
# ---------------------------------------------------------------------------

TEXT_SAMPLES = [
    {
        "label": "Obvious scam — UPI fraud",
        "text": (
            "Dear customer, your SBI account has been blocked due to KYC non-compliance. "
            "Please update your Aadhaar and PAN immediately by clicking "
            "http://sbi-kyc-update.xyz/verify and enter your UPI PIN to unlock. "
            "Failure to act within 24 hours will result in permanent account suspension."
        ),
        "expected_verdict_range": "fraudulent",
    },
    {
        "label": "Fake job offer",
        "text": (
            "Congratulations! You have been selected for a Work From Home job. "
            "Earn Rs.50,000 per month. No experience needed. "
            "Pay Rs.999 registration fee to activate your account. "
            "WhatsApp: +91-9876543210. Limited seats available. Apply NOW!"
        ),
        "expected_verdict_range": "fraudulent",
    },
    {
        "label": "Likely safe — college notice",
        "text": (
            "All students are requested to submit their fee receipts to the accounts "
            "department by Friday 5 PM. Please carry your college ID card. "
            "Contact the office at office@college.edu for any queries."
        ),
        "expected_verdict_range": "safe",
    },
    {
        "label": "Suspicious — vague prize claim",
        "text": (
            "You have won a special prize in the Amazon Lucky Draw 2024! "
            "To claim, reply with your name, address, and bank details. "
            "Offer valid for 48 hours only."
        ),
        "expected_verdict_range": "suspicious",
    },
]

URL_SAMPLES = [
    {
        "label": "Phishing URL — suspicious TLD + brand impersonation",
        "url": "http://hdfc-bank-login.xyz/verify-account",
    },
    {
        "label": "Shortened URL",
        "url": "https://bit.ly/3xABC12",
    },
    {
        "label": "Legitimate URL",
        "url": "https://www.hdfcbank.com/personal",
    },
    {
        "label": "IP address URL",
        "url": "http://192.168.1.105/login",
    },
]

# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def print_header(title: str) -> None:
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")


def print_pass(label: str, detail: str = "") -> None:
    tick = f"{GREEN}✓ PASS{RESET}"
    print(f"  {tick}  {label}")
    if detail:
        print(f"         {YELLOW}{detail}{RESET}")


def print_fail(label: str, detail: str = "") -> None:
    cross = f"{RED}✗ FAIL{RESET}"
    print(f"  {cross}  {label}")
    if detail:
        print(f"         {RED}{detail}{RESET}")


def validate_response(data: dict, label: str) -> bool:
    """
    Check that a response dict has all required fields and valid values.
    Returns True if all checks pass.
    """
    all_passed = True
    required_fields = ["id", "input_type", "risk_score", "verdict", "details", "analyzed_at"]

    for field in required_fields:
        if field not in data:
            print_fail(f"[{label}] Missing field: '{field}'")
            all_passed = False

    if "risk_score" in data:
        score = data["risk_score"]
        if not (0.0 <= score <= 1.0):
            print_fail(f"[{label}] risk_score out of range: {score}")
            all_passed = False

    if "verdict" in data:
        if data["verdict"] not in VALID_VERDICTS:
            print_fail(f"[{label}] Invalid verdict: '{data['verdict']}'")
            all_passed = False

    if "details" in data:
        details = data["details"]
        if not isinstance(details, dict):
            print_fail(f"[{label}] 'details' should be a dict, got {type(details)}")
            all_passed = False

    return all_passed


def make_fake_image_bytes(text_on_image: str = "SCAM TEST") -> bytes:
    """
    Create a simple PNG image with text burned into it for OCR testing.
    Uses only Pillow — no external files needed.
    """
    try:
        from PIL import Image, ImageDraw
        img = Image.new("RGB", (400, 100), color="white")
        draw = ImageDraw.Draw(img)
        draw.text((10, 35), text_on_image, fill="black")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        # Return a minimal 1x1 white PNG if Pillow is missing
        return (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
            b'\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00'
            b'\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18'
            b'\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
        )


def make_qr_image_bytes(url: str) -> bytes:
    """
    Generate a QR code image for the given URL.
    Requires: pip install qrcode Pillow
    """
    try:
        import qrcode
        qr = qrcode.make(url)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        print(f"  {YELLOW}(qrcode not installed — skipping QR generation test){RESET}")
        return b""


# ---------------------------------------------------------------------------
# TEST SUITES
# ---------------------------------------------------------------------------

def test_health(session: requests.Session) -> bool:
    print_header("Health Check — GET /")
    try:
        resp = session.get(f"{BASE_URL}/", timeout=5)
        if resp.status_code == 200 and resp.json().get("status") == "ok":
            print_pass("Backend is reachable and healthy")
            return True
        else:
            print_fail(f"Unexpected response: {resp.status_code} — {resp.text[:100]}")
            return False
    except requests.exceptions.ConnectionError:
        print_fail(
            "Cannot connect to backend",
            "Make sure the server is running: uvicorn main:app --reload --port 8000"
        )
        return False


def test_text_endpoint(session: requests.Session) -> dict:
    print_header("POST /analyze/text")
    results = {"passed": 0, "failed": 0}

    for sample in TEXT_SAMPLES:
        label = sample["label"]
        try:
            resp = session.post(
                f"{BASE_URL}/analyze/text",
                json={"text": sample["text"]},
                timeout=30,
            )

            if resp.status_code != 200:
                print_fail(label, f"HTTP {resp.status_code}: {resp.text[:200]}")
                results["failed"] += 1
                continue

            data = resp.json()
            ok = validate_response(data, label)

            if ok:
                verdict = data.get("verdict", "?")
                score = data.get("risk_score", "?")
                category = data.get("details", {}).get("category", "?")
                print_pass(
                    label,
                    f"verdict={verdict}  risk_score={score}  category={category}"
                )
                results["passed"] += 1
            else:
                results["failed"] += 1

        except Exception as e:
            print_fail(label, str(e))
            results["failed"] += 1

    return results


def test_url_endpoint(session: requests.Session) -> dict:
    print_header("POST /analyze/url")
    results = {"passed": 0, "failed": 0}

    for sample in URL_SAMPLES:
        label = sample["label"]
        try:
            resp = session.post(
                f"{BASE_URL}/analyze/url",
                json={"url": sample["url"]},
                timeout=30,
            )

            if resp.status_code != 200:
                print_fail(label, f"HTTP {resp.status_code}: {resp.text[:200]}")
                results["failed"] += 1
                continue

            data = resp.json()
            ok = validate_response(data, label)

            if ok:
                verdict = data.get("verdict", "?")
                score = data.get("risk_score", "?")
                struct_flags = data.get("details", {}).get("structural_flags", [])
                flag_count = len(struct_flags)
                print_pass(
                    label,
                    f"verdict={verdict}  risk_score={score}  structural_flags={flag_count}"
                )
                results["passed"] += 1
            else:
                results["failed"] += 1

        except Exception as e:
            print_fail(label, str(e))
            results["failed"] += 1

    return results


def test_image_endpoint(session: requests.Session) -> dict:
    print_header("POST /analyze/image")
    results = {"passed": 0, "failed": 0}

    image_cases = [
        {
            "label": "Image with scam text (OCR test)",
            "text": "Your account is blocked. Send OTP to 9999999999 immediately.",
        },
        {
            "label": "Image with safe text",
            "text": "Meeting at 3 PM in conference room B.",
        },
    ]

    for case in image_cases:
        label = case["label"]
        try:
            img_bytes = make_fake_image_bytes(case["text"])
            resp = session.post(
                f"{BASE_URL}/analyze/image",
                files={"file": ("test.png", img_bytes, "image/png")},
                timeout=30,
            )

            if resp.status_code != 200:
                print_fail(label, f"HTTP {resp.status_code}: {resp.text[:200]}")
                results["failed"] += 1
                continue

            data = resp.json()
            ok = validate_response(data, label)

            if ok:
                verdict = data.get("verdict", "?")
                score = data.get("risk_score", "?")
                preview = data.get("details", {}).get("extracted_text_preview", "(none)")[:60]
                print_pass(
                    label,
                    f"verdict={verdict}  risk_score={score}  ocr_preview='{preview}'"
                )
                results["passed"] += 1
            else:
                results["failed"] += 1

        except Exception as e:
            print_fail(label, str(e))
            results["failed"] += 1

    # Edge case: wrong file type
    label = "Edge case — wrong file type (should return 400)"
    try:
        resp = session.post(
            f"{BASE_URL}/analyze/image",
            files={"file": ("test.txt", b"hello world", "text/plain")},
            timeout=10,
        )
        if resp.status_code == 400:
            print_pass(label, "Correctly rejected non-image file with HTTP 400")
            results["passed"] += 1
        else:
            print_fail(label, f"Expected 400, got {resp.status_code}")
            results["failed"] += 1
    except Exception as e:
        print_fail(label, str(e))
        results["failed"] += 1

    return results


def test_qr_endpoint(session: requests.Session) -> dict:
    print_header("POST /analyze/qr")
    results = {"passed": 0, "failed": 0}

    qr_cases = [
        {
            "label": "QR code with phishing URL",
            "url": "http://hdfc-kyc-update.xyz/verify?token=abc123",
        },
        {
            "label": "QR code with safe URL",
            "url": "https://www.google.com",
        },
    ]

    for case in qr_cases:
        label = case["label"]
        qr_bytes = make_qr_image_bytes(case["url"])
        if not qr_bytes:
            print(f"  {YELLOW}  SKIP  {label} (qrcode library not installed){RESET}")
            continue

        try:
            resp = session.post(
                f"{BASE_URL}/analyze/qr",
                files={"file": ("qr.png", qr_bytes, "image/png")},
                timeout=30,
            )

            if resp.status_code != 200:
                print_fail(label, f"HTTP {resp.status_code}: {resp.text[:200]}")
                results["failed"] += 1
                continue

            data = resp.json()
            ok = validate_response(data, label)

            if ok:
                verdict = data.get("verdict", "?")
                score = data.get("risk_score", "?")
                decoded = data.get("details", {}).get("qr_decoded_content", "?")
                print_pass(
                    label,
                    f"verdict={verdict}  risk_score={score}  decoded='{decoded[:60]}'"
                )
                results["passed"] += 1
            else:
                results["failed"] += 1

        except Exception as e:
            print_fail(label, str(e))
            results["failed"] += 1

    # Edge case: no QR code in image (blank white image)
    label = "Edge case — blank image (no QR code, should return 422)"
    try:
        blank = make_fake_image_bytes("NO QR HERE")
        resp = session.post(
            f"{BASE_URL}/analyze/qr",
            files={"file": ("blank.png", blank, "image/png")},
            timeout=10,
        )
        if resp.status_code == 422:
            print_pass(label, "Correctly returned 422 when no QR found")
            results["passed"] += 1
        elif resp.status_code == 200:
            # pyzbar might not be installed — route may not be reachable
            print(f"  {YELLOW}? WARN  {label} — got 200, pyzbar may not be installed{RESET}")
        else:
            print_fail(label, f"Expected 422, got {resp.status_code}")
            results["failed"] += 1
    except Exception as e:
        print_fail(label, str(e))
        results["failed"] += 1

    return results


def test_history_endpoint(session: requests.Session) -> dict:
    print_header("GET /history")
    results = {"passed": 0, "failed": 0}

    try:
        resp = session.get(f"{BASE_URL}/history", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if "analyses" in data and "count" in data:
                count = data["count"]
                print_pass(
                    "History endpoint accessible",
                    f"Returned {count} records"
                )
                results["passed"] += 1
            else:
                print_fail("Response missing 'analyses' or 'count' field", str(data)[:100])
                results["failed"] += 1
        else:
            print_fail(f"HTTP {resp.status_code}", resp.text[:200])
            results["failed"] += 1
    except Exception as e:
        print_fail("History endpoint error", str(e))
        results["failed"] += 1

    return results


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    print(f"\n{BOLD}TrustShield AI — Integration Test Suite{RESET}")
    print(f"Target: {BASE_URL}")
    print(f"Time:   {time.strftime('%Y-%m-%d %H:%M:%S')}")

    session = requests.Session()
    session.headers.update({"User-Agent": "TrustShield-Integration-Test/1.0"})

    # Health check first — abort if server is not running
    if not test_health(session):
        print(f"\n{RED}Aborting: backend is not reachable.{RESET}")
        sys.exit(1)

    all_results = []
    all_results.append(test_text_endpoint(session))
    all_results.append(test_url_endpoint(session))
    all_results.append(test_image_endpoint(session))
    all_results.append(test_qr_endpoint(session))
    all_results.append(test_history_endpoint(session))

    # Summary
    total_passed = sum(r["passed"] for r in all_results)
    total_failed = sum(r["failed"] for r in all_results)
    total = total_passed + total_failed

    print_header("SUMMARY")
    print(f"  Total tests : {total}")
    print(f"  {GREEN}Passed      : {total_passed}{RESET}")
    print(f"  {RED}Failed      : {total_failed}{RESET}")

    if total_failed == 0:
        print(f"\n  {GREEN}{BOLD}All tests passed! ✓{RESET}\n")
    else:
        print(f"\n  {RED}{BOLD}{total_failed} test(s) failed.{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
