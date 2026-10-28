import re
import secrets

def rot13(text: str) -> str:
    """Encode/Decode ROT13 cipher."""
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return (
        f"🔄 *ROT13 Result:*\n"
        f"`{''.join(result)}`"
    )

def caesar_cipher(text: str, shift: int) -> str:
    """Caesar cipher with custom shift (+ or -)."""
    result = []
    shift = shift % 26
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(char)
    return (
        f"🏛️ *Caesar Cipher (Shift {shift}):*\n"
        f"`{''.join(result)}`"
    )

def defang_indicator(target: str) -> str:
    """Defang dangerous URLs/IPs so they cannot be clicked accidentally."""
    cleaned = target.strip()
    cleaned = re.sub(r"^https://", "hxxps://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^http://", "hxxp://", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.replace("://", "[://]")
    cleaned = cleaned.replace(".", "[.]")
    return (
        f"🛡️ *Defanged Indicator:*\n\n"
        f"`{cleaned}`\n\n"
        f"💡 _Safe for reports and threat tickets without triggering accidental clicks._"
    )

def refang_indicator(target: str) -> str:
    """Refang sanitized URLs/IPs back to operational format."""
    cleaned = target.strip()
    cleaned = cleaned.replace("[.]", ".").replace("(.)", ".")
    cleaned = cleaned.replace("[://]", "://").replace("(://)", "://")
    cleaned = re.sub(r"^hxxps://", "https://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^hxxp://", "http://", cleaned, flags=re.IGNORECASE)
    return (
        f"🔓 *Refanged Indicator:*\n\n"
        f"`{cleaned}`"
    )

QUIZ_QUESTIONS = [
    {
        "q": "Which port is used by default for Secure Shell (SSH)?",
        "options": ["21", "22", "23", "443"],
        "correct": 1,
        "expl": "Port 22 is the standard TCP port for SSH encrypted remote logins.",
    },
    {
        "q": "What type of attack involves an attacker placing themselves between a client and a server?",
        "options": ["Brute-force", "SQL Injection", "Man-in-the-Middle (MITM)", "Buffer Overflow"],
        "correct": 2,
        "expl": "MITM attacks intercept and potentially alter communication between two parties.",
    },
    {
        "q": "Which HTTP security header protects against Clickjacking attacks?",
        "options": ["X-Frame-Options", "Strict-Transport-Security", "Server", "X-XSS-Protection"],
        "correct": 0,
        "expl": "X-Frame-Options (or CSP frame-ancestors) prevents the site from being rendered in an iframe.",
    },
    {
        "q": "What is the primary purpose of Salting passwords before hashing?",
        "options": ["Speed up authentication", "Prevent rainbow table / precomputed attacks", "Compress password size", "Encrypt the database"],
        "correct": 1,
        "expl": "A unique salt ensures that identical passwords produce distinct hashes, rendering rainbow tables useless.",
    },
    {
        "q": "Which vulnerability allows attackers to run unauthorized SQL queries by injecting malicious user input?",
        "options": ["CSRF", "SQL Injection (SQLi)", "SSRF", "Directory Traversal"],
        "correct": 1,
        "expl": "SQLi occurs when untrusted input is directly concatenated into database queries.",
    },
    {
        "q": "What does the CVSS score of 9.8 indicate?",
        "options": ["Low severity", "Medium severity", "High severity", "Critical severity"],
        "correct": 3,
        "expl": "CVSS base scores between 9.0 and 10.0 represent Critical severity vulnerabilities.",
    },
]

def get_random_quiz():
    """Select a random quiz question."""
    q_data = secrets.choice(QUIZ_QUESTIONS)
    return q_data
