# =============================================================================
# TrustShield AI — AI Analysis Service (Groq LLM-powered Fraud Detection)
# =============================================================================
#
# This module sends text to Groq's LLM API for fraud analysis.
# The LLM acts as a digital fraud detection expert, returning a structured
# JSON response with trust score, verdict, category, red flags, and explanation.
#
# Dependencies:
#   - groq (Groq Python client)
#   - python-dotenv (for loading GROQ_API_KEY from .env)
#
# Environment Variables:
#   - GROQ_API_KEY: Your Groq API key (required)
#
# =============================================================================

import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

# Initialize the Groq client with the API key from environment.
groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# ---------------------------------------------------------------------------
# FRAUD DETECTION PROMPT TEMPLATE
#
# This prompt instructs the LLM to analyze text for fraud indicators and
# return a structured JSON response.  The template uses Python's .format()
# with escaped braces {{ }} for the JSON structure.
# ---------------------------------------------------------------------------

FRAUD_PROMPT_TEMPLATE = """
You are a digital fraud detection expert. Analyze the following text extracted from a user-submitted screenshot or message.

Respond ONLY with a valid JSON object — no markdown, no preamble, no explanation outside the JSON.

Text to analyze:
\"\"\"
{extracted_text}
\"\"\"

Return this exact JSON structure:
{{
  "trust_score": <integer 0-100, where 100 is fully trustworthy>,
  "verdict": "<one of: Safe | Suspicious | Scam>",
  "category": "<one of: Phishing | Fake Job Offer | Fake Internship | UPI Payment Fraud | Lottery Scam | Banking/KYC Scam | Scholarship Scam | Fake Customer Support | Malicious Link | Unknown>",
  "red_flags": [<list of specific warning signs found, as plain strings>],
  "explanation": "<2-3 sentence plain English explanation of your verdict, suitable for a non-technical user>"
}}

If the text appears completely safe and legitimate, set trust_score above 80 and red_flags to an empty array.
"""


def build_prompt(extracted_text: str) -> str:
    """
    Format the fraud detection prompt with the given text.

    Args:
        extracted_text: The text to analyze (from OCR or direct input).

    Returns:
        The formatted prompt string ready to send to the LLM.
    """
    return FRAUD_PROMPT_TEMPLATE.format(extracted_text=extracted_text)


def analyze_text(text: str) -> dict:
    """
    Send text to Groq's LLM for fraud analysis.

    Flow:
        1. Build the fraud detection prompt with the input text.
        2. Send to Groq's chat completion API (using llama-3.3-70b-versatile).
        3. Parse the JSON response from the LLM.
        4. Return the structured result.

    Args:
        text: The text to analyze for fraud indicators.

    Returns:
        A dictionary with keys:
            - trust_score (int): 0-100, where 100 is fully trustworthy
            - verdict (str): "Safe", "Suspicious", or "Scam"
            - category (str): Type of fraud detected
            - red_flags (list[str]): Specific warning signs found
            - explanation (str): Plain English explanation

        If the LLM call fails, returns a fallback dict indicating the error.
    """
    prompt = build_prompt(text)

    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a fraud detection expert. Always respond with valid JSON only."
                },
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.3,       # Low temperature for consistent, factual analysis
            max_tokens=1024,
        )

        # Extract the response content
        response_text = chat_completion.choices[0].message.content.strip()

        # Clean up potential markdown code block wrapping
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()

        # Parse the JSON response
        result = json.loads(response_text)

        # Ensure all expected keys are present with defaults
        return {
            "trust_score": result.get("trust_score", 50),
            "verdict": result.get("verdict", "Suspicious"),
            "category": result.get("category", "Unknown"),
            "red_flags": result.get("red_flags", []),
            "explanation": result.get("explanation", "Analysis completed."),
        }

    except json.JSONDecodeError as e:
        return {
            "trust_score": 50,
            "verdict": "Suspicious",
            "category": "Unknown",
            "red_flags": ["AI response could not be parsed"],
            "explanation": f"The AI analysis returned a malformed response. Error: {str(e)}",
        }
    except Exception as e:
        return {
            "trust_score": 50,
            "verdict": "Suspicious",
            "category": "Unknown",
            "red_flags": ["AI service unavailable"],
            "explanation": f"Could not complete AI analysis. Error: {str(e)}",
        }
