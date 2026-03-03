import os
import json
from google import genai

# Setup API Key securely from environment
api_key = os.getenv("GOOGLE_API_KEY")
if not api_key:
    # We define the client as None initially to avoid NameError if needed,
    # but the analyze_code function handles the check.
    client = None
else:
    client = genai.Client(api_key=api_key)

SYSTEM_PROMPT = """
You are a security analysis engine.
Your only task is to analyze AI-generated Python code for security vulnerabilities and return a strictly structured JSON risk report.

You are not a chatbot.
You are not allowed to provide explanations outside JSON.
You must follow the schema exactly.

Scope Rules (Non-Negotiable):
1. Analyze Python code only.
2. Focus strictly on security vulnerabilities.
3. Do NOT analyze performance or code style.
4. Do NOT analyze logical correctness unless it creates a security risk.
5. Do NOT generate new code unless it is part of a fix suggestion.
6. Maximum 5 vulnerabilities.
7. If no vulnerabilities exist, return an empty vulnerabilities array.
8. If input is not valid Python code, return a Low risk report with 0.0 confidence.

Security Categories:
SQL injection, Command injection, Deserialization, Unsafe eval/exec, Hardcoded secrets, Insecure file handling, Path traversal, Insecure authentication, Insecure cryptography, Dependency misuse, Insecure network usage.

Output Requirements (STRICT):
Return ONLY valid JSON matching this schema:
{
  "risk_level": "Low | Medium | High",
  "vulnerabilities": [
    {
      "type": "string",
      "severity": "Low | Medium | High | Critical",
      "line_number": integer,
      "description": "string",
      "fix_suggestion": "string"
    }
  ],
  "confidence_score": float
}
Rules:
- risk_level must reflect the highest severity found.
- line_number must correspond to actual line in provided code.
- confidence_score must be between 0.0 and 1.0.
- No additional keys allowed. No markdown. No commentary. No text outside JSON.
- If vulnerabilities exceed 5, return the 5 most severe.
"""

def analyze_code(code_string):
    """
    Analyzes Python code for security vulnerabilities using Gemini as a strict engine.
    Uses the new google.genai Client interface.
    """
    if not client:
        return {
            "status": "analysis_error",
            "message": "GOOGLE_API_KEY is not set in the environment.",
            "confidence_score": 0.0
        }
        
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=[SYSTEM_PROMPT, f"Code:\n{code_string}"]
        )
        
        # Clean up response to ensure it's valid JSON
        text = response.text.replace('```json', '').replace('```', '').strip()
        report = json.loads(text)
        
        # Validation of required keys (minimal)
        required_keys = ["risk_level", "vulnerabilities", "confidence_score"]
        if not all(k in report for k in required_keys):
             raise ValueError("Missing keys in LLM response")
             
        return {
            "status": "success",
            **report
        }
        
    except Exception as e:
        # Fallback if AI fails or returns invalid JSON
        return {
            "status": "analysis_error",
            "message": str(e),
            "confidence_score": 0.0
        }
