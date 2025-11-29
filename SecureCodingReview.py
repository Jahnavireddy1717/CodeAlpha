import re
import os
import datetime

LOG_FILE = "secure_review.log"

VULNERABILITY_PATTERNS = {
    "Hardcoded Password": r'password\s*=\s*["\'].*["\']',
    "SQL Injection": r'(SELECT .* FROM .WHERE.["\'].*["\'])',
    "Unsafe eval()": r'eval\(',
    "Insecure File Handling": r'open\(.["\']w["\'].\)'
}

def log_finding(vuln_type, line, file_path):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{timestamp}] {vuln_type} detected in {file_path}: {line.strip()}"
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")
    print(f"[ALERT] {message}")

def review_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                for vuln_type, pattern in VULNERABILITY_PATTERNS.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        log_finding(vuln_type, f"Line {line_no}: {line}", file_path)
    except:
        pass

def review_directory(directory_path):
    print("=== Secure Code Review Started ===")
    print(f"Scanning directory: {directory_path}")
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith((".java", ".py")):
                review_file(os.path.join(root, file))
    print("=== Review Completed ===")
    print(f"Findings logged in {LOG_FILE}")

if _name_ == "_main_":
    path_to_review = input("Enter the path of the code directory to review: ").strip()
    if os.path.exists(path_to_review):
        review_directory(path_to_review)
    else:
        print("Invalid directory path!")