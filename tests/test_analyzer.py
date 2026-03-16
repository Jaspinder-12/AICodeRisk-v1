import unittest
import sys
import os
import json
from unittest.mock import patch, MagicMock

# Add backend to path so we can import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

from analyzer import analyze_code

class TestAnalyzer(unittest.TestCase):
    @patch('analyzer.client', None)
    def test_missing_api_key(self):
        result = analyze_code("print('hello')")
        self.assertEqual(result["status"], "analysis_error")
        self.assertIn("GOOGLE_API_KEY is not set", result["message"])

    @patch('analyzer.client')
    @patch('analyzer.run_bandit_scan')
    def test_analyzer_success_handling(self, mock_run_bandit_scan, mock_client):
        # Mock Bandit output
        mock_run_bandit_scan.return_value = {"results": [], "errors": []}
        
        # Mock Gemini response
        mock_response = MagicMock()
        mock_response.text = json.dumps({
            "risk_level": "Low", 
            "vulnerabilities": [], 
            "confidence_score": 1.0
        })
        
        # Ensure the patched client behaves correctly
        mock_client.models.generate_content.return_value = mock_response
        
        code = "def add(a, b):\n    return a + b"
        result = analyze_code(code)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["risk_level"], "Low")

if __name__ == '__main__':
    unittest.main()
