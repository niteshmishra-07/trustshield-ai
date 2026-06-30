# =============================================================================
# TrustShield AI — OCR Service (Tesseract-based Image Text Extraction)
# =============================================================================
#
# This module extracts text from uploaded images using Tesseract OCR.
# It preprocesses images (grayscale, contrast boost, sharpening) to improve
# OCR accuracy before passing them to Tesseract.
#
# Dependencies:
#   - pytesseract (Python wrapper for Tesseract OCR engine)
#   - Pillow (PIL fork for image manipulation)
#   - Tesseract OCR must be installed on the system
#
# =============================================================================

import os
import shutil
import pytesseract
from PIL import Image, ImageFilter, ImageEnhance
import io
from dotenv import load_dotenv

load_dotenv()

# Resolve the Tesseract binary path:
#   1. Explicit TESSERACT_CMD env var, if set (works on any OS).
#   2. Auto-detect via PATH (works out of the box on Linux/Mac, and on
#      Windows if Tesseract's install dir was added to PATH).
#   3. Fall back to the default Windows install location as a last resort.
# This avoids hardcoding a Windows-only path that breaks for teammates on
# other operating systems or with a different install location.
_configured_cmd = os.environ.get("TESSERACT_CMD")
_detected_cmd = shutil.which("tesseract")

tesseract_cmd = (
    _configured_cmd
    or _detected_cmd
    or r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)
pytesseract.pytesseract.tesseract_cmd = tesseract_cmd


def preprocess_image(image: Image.Image) -> Image.Image:
    """
    Improve OCR accuracy by preprocessing the image.
    Converts to grayscale and boosts contrast.

    Steps:
        1. Convert to grayscale ("L" mode) — reduces noise from color channels.
        2. Boost contrast by 2x — makes text stand out against background.
        3. Apply sharpening filter — crisps up blurry text edges.

    Args:
        image: A PIL Image object in any color mode.

    Returns:
        A preprocessed PIL Image in grayscale, ready for OCR.
    """
    # Convert to grayscale
    image = image.convert("L")

    # Boost contrast
    enhancer = ImageEnhance.Contrast(image)
    image = enhancer.enhance(2.0)

    # Sharpen slightly
    image = image.filter(ImageFilter.SHARPEN)

    return image


def extract_text_from_image(image_bytes: bytes) -> str:
    """
    Extract text from raw image bytes using Tesseract OCR.

    Flow:
        1. Load the raw bytes into a PIL Image via io.BytesIO.
        2. Preprocess (grayscale, contrast, sharpen) for better accuracy.
        3. Run Tesseract OCR to extract text.
        4. Strip whitespace and return the result.

    Args:
        image_bytes: Raw bytes of an image file (PNG, JPEG, etc.).

    Returns:
        The extracted text as a string. Returns empty string if no text found.

    Raises:
        pytesseract.TesseractNotFoundError: If Tesseract is not installed at
            the configured path.
        PIL.UnidentifiedImageError: If the bytes don't represent a valid image.
    """
    # Load bytes into a PIL Image
    image = Image.open(io.BytesIO(image_bytes))

    # Preprocess for better OCR accuracy
    processed = preprocess_image(image)

    # Run Tesseract OCR
    try:
        extracted_text = pytesseract.image_to_string(processed)
    except pytesseract.TesseractNotFoundError:
        raise RuntimeError(
            f"Tesseract OCR binary not found at '{tesseract_cmd}'. "
            "Install it from https://github.com/UB-Mannheim/tesseract/wiki (Windows) "
            "or `apt install tesseract-ocr` (Linux), then set TESSERACT_CMD in your .env "
            "if it's not on your PATH."
        )

    return extracted_text.strip()
