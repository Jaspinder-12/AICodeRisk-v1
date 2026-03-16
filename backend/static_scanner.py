import json
import subprocess
import sys

def run_bandit_scan(file_path: str) -> dict:
    """
    Run Bandit security analysis on a Python file.

    Args:
        file_path: Path to the temporary Python file to scan.

    Returns:
        Parsed JSON output from Bandit.
    """
    try:
        # Run bandit with JSON output format
        # bandit returns 0 if no issues found, 1 if issues found, 2 if error
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-f", "json", "-q", file_path],
            capture_output=True,
            text=True,
            check=False
        )
        
        # Parse the JSON output
        if result.stdout:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"errors": [{"reason": "Failed to parse Bandit JSON output", "output": result.stdout}]}
        else:
            if result.stderr:
                 return {"errors": [{"reason": "Bandit execution error", "output": result.stderr}]}
            # Empty output, assume no results and no errors
            return {"results": [], "errors": []}
            
    except Exception as e:
        return {"errors": [{"reason": str(e)}]}
