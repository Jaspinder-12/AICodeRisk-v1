import re

def detect_static_vulnerabilities(code: str) -> list:
    """
    Deterministic static analysis for common Python security vulnerabilities.
    
    Scans for patterns including:
    - Unsafe evaluation (eval, exec)
    - OS command execution (os.system, subprocess)
    - Insecure deserialization (pickle.loads)
    - Input manipulation
    
    Args:
        code: Python source code to analyze.
        
    Returns:
        List of detected vulnerabilities with their details.
    """
    vulnerabilities = []
    lines = code.split('\n')

    # Define regex patterns for static scanning
    patterns = [
        {
            "regex": r"\beval\(",
            "type": "Unsafe eval",
            "severity": "High",
            "description": "The 'eval()' function can execute arbitrary code, leading to remote code execution (RCE).",
            "fix_suggestion": "Avoid using 'eval()'. Use safer alternatives like 'ast.literal_eval()' for parsing literals."
        },
        {
            "regex": r"\bexec\(",
            "type": "Unsafe exec",
            "severity": "Critical",
            "description": "The 'exec()' function executes dynamic Python code, which is extremely dangerous if input is untrusted.",
            "fix_suggestion": "Remove 'exec()' usage. Refactor code to use pre-defined functions or logic."
        },
        {
            "regex": r"os\.system\(",
            "type": "Command Injection",
            "severity": "Critical",
            "description": "Using 'os.system()' with external input can lead to OS command injection.",
            "fix_suggestion": "Use the 'subprocess' module with 'shell=False' and pass arguments as a list."
        },
        {
            "regex": r"subprocess\.Popen\(",
            "type": "Command Injection Risk",
            "severity": "Medium",
            "description": "Using 'subprocess.Popen' requires careful argument handling to avoid injection.",
            "fix_suggestion": "Ensure 'shell=False' is used and arguments are passed as a list."
        },
        {
            "regex": r"subprocess\.run\(.*shell=True",
            "type": "Command Injection",
            "severity": "High",
            "description": "Calling 'subprocess.run()' with 'shell=True' is dangerous as it invokes the shell.",
            "fix_suggestion": "Set 'shell=False' and provide the command and arguments as a list."
        },
        {
            "regex": r"pickle\.loads\(",
            "type": "Insecure Deserialization",
            "severity": "High",
            "description": "Deserializing untrusted data with 'pickle.loads()' can lead to arbitrary code execution.",
            "fix_suggestion": "Use safer serialization formats like JSON or 'marshal' (with caution), or cryptographically sign the data."
        },
        {
            "regex": r"eval\(.*input\(",
            "type": "Remote Code Execution",
            "severity": "Critical",
            "description": "Nesting 'input()' inside 'eval()' allows users to execute arbitrary code directly.",
            "fix_suggestion": "Never use 'eval(input())'. Use 'int()', 'float()', or other specific type conversions."
        }
    ]

    for line_num, line in enumerate(lines, 1):
        # Basic check for shell=True in more generic subprocess calls if not already caught
        if "shell=True" in line and ("subprocess" in line or "os.popen" in line):
            if not any(re.search(p["regex"], line) for p in patterns if p["type"] == "Command Injection"):
                 vulnerabilities.append({
                    "type": "Insecure Shell Execution",
                    "severity": "High",
                    "line_number": line_num,
                    "description": "Use of 'shell=True' detected in a shell-related function call.",
                    "fix_suggestion": "Set 'shell=False' to prevent shell injection vulnerabilities."
                })

        for p in patterns:
            if re.search(p["regex"], line):
                vulnerabilities.append({
                    "type": p["type"],
                    "severity": p["severity"],
                    "line_number": line_num,
                    "description": p["description"],
                    "fix_suggestion": p["fix_suggestion"]
                })

    return vulnerabilities
