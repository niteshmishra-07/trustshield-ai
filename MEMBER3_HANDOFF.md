# MEMBER3_HANDOFF.md — Integration Guide for Member 3's Services

## What's Been Integrated

Member 3 built two service modules for TrustShield AI:

1. **`services/ocr_service.py`** — Tesseract OCR-based image text extraction
2. **`services/ai_service.py`** — Groq LLM-powered fraud detection analysis

These services have been integrated into the FastAPI routes in `routes/analyze.py`.

---

## How It Works

### For Image Uploads (POST /analyze/image)
```python
from services.ocr_service import extract_text_from_image
from services.ai_service import analyze_text

# 1. Read image bytes from upload
contents = await file.read()

# 2. Extract text from image via Tesseract OCR
text = extract_text_from_image(contents)

# 3. Analyze extracted text for fraud via Groq AI
result = analyze_text(text)
```

### For Raw Text (POST /analyze/text)
```python
from services.ai_service import analyze_text

# Direct analysis — no OCR needed
result = analyze_text(raw_text)
```

### For URLs (POST /analyze/url)
```python
from services.ai_service import analyze_text

# Analyze the URL string for fraud patterns
result = analyze_text(url_string)
```

---

## AI Response Format

The `analyze_text()` function returns a dictionary:
```json
{
  "trust_score": 25,
  "verdict": "Scam",
  "category": "Phishing",
  "red_flags": ["Urgency tactics", "Suspicious link", "Request for personal info"],
  "explanation": "This message contains classic phishing indicators..."
}
```

### Score Conversion
- AI returns `trust_score` (0-100, higher = safer)
- API exposes `risk_score` (0.0-1.0, higher = riskier)
- Formula: `risk_score = (100 - trust_score) / 100`

### Verdict Mapping
| AI Verdict   | API Verdict    |
|-------------|---------------|
| Safe        | safe          |
| Suspicious  | suspicious    |
| Scam        | fraudulent    |

---

## Environment Variables Required

Add these to your `.env` file:

```env
# Groq API key (REQUIRED for AI analysis)
GROQ_API_KEY=your_groq_api_key_here

# Tesseract path (only needed for image OCR)
TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
```

## Dependencies Added

```
pytesseract    # Python wrapper for Tesseract OCR
Pillow         # Image preprocessing (grayscale, contrast, sharpen)
groq           # Groq API client for LLM inference
```

Install with: `pip install pytesseract Pillow groq`

---

## File Structure After Integration

```
TrustShield/
├── main.py                    # FastAPI app entry point (unchanged)
├── database.py                # MongoDB connection (unchanged)
├── models.py                  # Pydantic models (unchanged)
├── requirements.txt           # Updated with new deps
├── .env                       # Updated with GROQ_API_KEY
├── MEMBER3_HANDOFF.md         # This file
├── routes/
│   ├── __init__.py
│   ├── analyze.py             # Updated — uses real AI services
│   └── history.py             # Unchanged
└── services/                  # NEW — Member 3's services
    ├── __init__.py
    ├── ocr_service.py         # Tesseract OCR text extraction
    └── ai_service.py          # Groq LLM fraud analysis
```
