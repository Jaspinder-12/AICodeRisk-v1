import os
import tempfile
import pytest
import sys

# Ensure backend module can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))
from static_scanner import run_bandit_scan

def write_temp_script(code_content: str) -> str:
    """Helper to write code to a temp file and return its path."""
    fd, temp_path = tempfile.mkstemp(suffix=".py", text=True)
    with os.fdopen(fd, 'w') as f:
        f.write(code_content)
    return temp_path

def test_eval_vulnerability():
    code = "user_input = input('Enter math: ')\nresult = eval(user_input)\nprint(result)\n"
    temp_path = write_temp_script(code)
    try:
        report = run_bandit_scan(temp_path)
        assert report, "Bandit should return a report"
        assert "results" in report, "Report should contain 'results'"
        
        # Check if B307 (eval) is caught
        test_ids = [issue.get("test_id") for issue in report.get("results", [])]
        assert "B307" in test_ids, "Should detect eval() vulnerability (B307)"
    finally:
        os.remove(temp_path)

def test_os_system_command_injection():
    code = "import os\ncmd = 'ls ' + input('dir: ')\nos.system(cmd)\n"
    temp_path = write_temp_script(code)
    try:
        report = run_bandit_scan(temp_path)
        assert "results" in report
        
        test_ids = [issue.get("test_id") for issue in report.get("results", [])]
        assert "B605" in test_ids, "Should detect os.system() vulnerability (B605)"
    finally:
        os.remove(temp_path)

def test_subprocess_shell_true():
    code = "import subprocess\nsubprocess.run('ls -l', shell=True)\n"
    temp_path = write_temp_script(code)
    try:
        report = run_bandit_scan(temp_path)
        assert "results" in report
        
        test_ids = [issue.get("test_id") for issue in report.get("results", [])]
        assert "B602" in test_ids, "Should detect subprocess with shell=True (B602)"
    finally:
        os.remove(temp_path)

def test_clean_python_script():
    code = "def add(a, b):\n    return a + b\n\nprint(add(2, 3))\n"
    temp_path = write_temp_script(code)
    try:
        report = run_bandit_scan(temp_path)
        assert "results" in report
        assert len(report.get("results", [])) == 0, "Clean script should have 0 vulnerabilities"
    finally:
        os.remove(temp_path)
