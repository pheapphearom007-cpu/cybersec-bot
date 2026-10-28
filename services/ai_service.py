import os
from pathlib import Path
from dotenv import load_dotenv
from google import genai
from google.genai import types

# Ensure .env is loaded from the project root
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

SYSTEM_INSTRUCTION = """
You are CyberSec AI, an expert cybersecurity assistant and defensive security educator.
Your role:
1. Provide concise, clear, and actionable cybersecurity explanations, threat intelligence, and defense strategies.
2. Teach ethical hacking concepts from a defensive/educational perspective (OWASP Top 10, network security, cryptography, mitigation).
3. Never generate functional malware, exploit payloads, or malicious scripts. If asked for exploits, pivot to explaining the underlying vulnerability and remediation/patching steps.
4. Keep replies formatted with clean Markdown, bullet points, and concise text under 350 words so it fits well in Telegram chats.
"""

OFFLINE_TOPICS = {
    "phishing": (
        "🎣 *Phishing:* A social engineering attack where attackers impersonate trustworthy entities "
        "(e.g., banks, IT admins) to trick victims into revealing sensitive data like passwords or credit card numbers.\n\n"
        "🛡️ *Defense:* Multi-factor authentication (MFA), domain verification, employee training, and email filtering (SPF, DKIM, DMARC)."
    ),
    "ransomware": (
        "🔒 *Ransomware:* Malware that encrypts victim files and demands a ransom payment to restore access.\n\n"
        "🛡️ *Defense:* Immutable offline backups, network segmentation, least privilege access, and keeping systems patched."
    ),
    "sql injection": (
        "💉 *SQL Injection (SQLi):* Attack where untrusted input is concatenated into database queries, allowing attackers to read or tamper with the database.\n\n"
        "🛡️ *Defense:* Always use parameterized queries (Prepared Statements) or an ORM, and validate all inputs."
    ),
    "xss": (
        "🌐 *Cross-Site Scripting (XSS):* Vulnerability allowing attackers to inject malicious client-side scripts into web pages viewed by other users.\n\n"
        "🛡️ *Defense:* Context-aware output encoding, Content Security Policy (CSP), and HTTPOnly cookies."
    ),
    "zero-day": (
        "⏳ *Zero-Day Vulnerability:* A software security flaw that is unknown to the vendor or has no public patch available yet.\n\n"
        "🛡️ *Defense:* Defense-in-depth, Web Application Firewalls (WAF), endpoint detection and response (EDR), and rapid patch deployment."
    ),
}

def ask_cyber_ai(question: str) -> str:
    """Send question to Gemini AI or fallback to offline knowledge base."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    if not api_key:
        q_lower = question.lower()
        for key, text in OFFLINE_TOPICS.items():
            if key in q_lower:
                return f"{text}\n\n💡 *Tip:* To ask custom questions, add your free `GEMINI_API_KEY` to the `.env` file."

        return (
            "🤖 *AI Assistant is not configured yet.*\n\n"
            "To enable live AI answers for any cybersecurity question:\n"
            "1. Get a free API key at [Google AI Studio](https://aistudio.google.com/)\n"
            "2. Add `GEMINI_API_KEY=your_key` into the `.env` file\n"
            "3. Restart the bot!"
        )

    # Try available Gemini models in order of priority
    candidate_models = ["gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-3.8-flash"]

    try:
        client = genai.Client(api_key=api_key)
        
        last_error = None
        for model_name in candidate_models:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=question,
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_INSTRUCTION,
                        max_output_tokens=800,
                    ),
                )
                if response.text:
                    return response.text
            except Exception as model_err:
                last_error = model_err
                continue

        if last_error:
            return f"⚠️ Error querying AI assistant: {str(last_error)}"
        return "⚠️ Received empty response from AI service."

    except Exception as e:
        return f"⚠️ Error querying AI assistant: {str(e)}"
