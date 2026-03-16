import os
import requests
import json
import logging

logger = logging.getLogger(__name__)

HF_API_URL = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2"

def explain_vulnerabilities(prompt: str) -> str:
    """
    Sends the vulnerability explanation prompt to the Hugging Face inference API
    and returns the generated explanation text.
    """
    token = os.getenv("HF_API_TOKEN")
    if not token:
        logger.error("HF_API_TOKEN environment variable is not set.")
        raise ValueError("Hugging Face API token is missing")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": 1024,
            "return_full_text": False
        }
    }

    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        
        # The API usually returns a list with one dictionary
        result = response.json()
        if isinstance(result, list) and len(result) > 0 and "generated_text" in result[0]:
            return result[0]["generated_text"]
        elif isinstance(result, dict) and "generated_text" in result:
             return result["generated_text"]
        else:
             logger.error(f"Unexpected response format from Hugging Face: {result}")
             raise ValueError("Unexpected API response format")

    except Exception as e:
        logger.error(f"Failed to generate explanation with Hugging Face: {e}")
        raise
