import hashlib
import base64
import urllib.parse
import secrets
import string
import re
import math

def generate_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password."""
    if length < 8:
        length = 8
    elif length > 64:
        length = 64

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    # Ensure at least one lowercase, uppercase, digit, and special char
    pwd = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+"),
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    password = "".join(pwd)

    # Calculate entropy: log2(charset_size^length)
    entropy = length * math.log2(len(alphabet))

    return (
        f"🔐 *Generated Secure Password ({length} chars):*\n\n"
        f"`{password}`\n\n"
        f"• *Entropy:* `{entropy:.1f} bits`\n"
        f"• *Status:* 🛡️ Very Strong\n"
        f"💡 _Tap the password above to copy it._"
    )

def check_password_strength(password: str) -> str:
    """Analyze password complexity and strength locally."""
    if not password:
        return "⚠️ Please provide a password to test: `/checkpass <password>`"

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/~`]", password))

    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_special: charset_size += 32

    entropy = length * math.log2(charset_size) if charset_size > 0 else 0

    if entropy < 36:
        rating = "🔴 Very Weak (Vulnerable to brute-force)"
    elif entropy < 60:
        rating = "🟠 Moderate (Consider adding length & symbols)"
    elif entropy < 80:
        rating = "🟡 Strong"
    else:
        rating = "🟢 Very Strong (Resistant to offline brute-force)"

    return (
        f"🛡️ *Password Strength Analysis*\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"• *Length:* `{length}` characters\n"
        f"• *Entropy:* `{entropy:.1f} bits`\n"
        f"• *Rating:* {rating}\n\n"
        f"*Complexity Breakdown:*\n"
        f"{'✅' if has_lower else '❌'} Lowercase letters (a-z)\n"
        f"{'✅' if has_upper else '❌'} Uppercase letters (A-Z)\n"
        f"{'✅' if has_digit else '❌'} Digits (0-9)\n"
        f"{'✅' if has_special else '❌'} Special symbols (!@#$%...)\n"
    )

def compute_hashes(text: str) -> str:
    """Calculate MD5, SHA-1, SHA-256, and SHA-512 hashes."""
    if not text:
        return "⚠️ Usage: `/hash <text>`\nExample: `/hash admin123`"

    b = text.encode("utf-8")
    md5 = hashlib.md5(b).hexdigest()
    sha1 = hashlib.sha1(b).hexdigest()
    sha256 = hashlib.sha256(b).hexdigest()
    sha512 = hashlib.sha512(b).hexdigest()

    return (
        f"🔑 *Hash Fingerprints for:* `{text[:50]}`\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"• *MD5:*\n`{md5}`\n\n"
        f"• *SHA-1:*\n`{sha1}`\n\n"
        f"• *SHA-256:*\n`{sha256}`\n\n"
        f"• *SHA-512:*\n`{sha512}`\n"
    )

def encode_text(enc_type: str, text: str) -> str:
    """Encode text to Base64, URL, or Hex."""
    enc_type = enc_type.lower().strip()
    try:
        if enc_type in ("b64", "base64"):
            encoded = base64.b64encode(text.encode("utf-8")).decode("utf-8")
            return f"🔤 *Base64 Encoded:*\n`{encoded}`"
        elif enc_type == "url":
            encoded = urllib.parse.quote(text)
            return f"🔤 *URL Encoded:*\n`{encoded}`"
        elif enc_type == "hex":
            encoded = text.encode("utf-8").hex()
            return f"🔤 *Hex Encoded:*\n`{encoded}`"
        else:
            return "⚠️ Supported types: `base64`, `url`, `hex`\nExample: `/encode base64 Hello World`"
    except Exception as e:
        return f"⚠️ Encoding error: {str(e)}"

def decode_text(dec_type: str, text: str) -> str:
    """Decode text from Base64, URL, or Hex."""
    dec_type = dec_type.lower().strip()
    try:
        if dec_type in ("b64", "base64"):
            decoded = base64.b64decode(text.encode("utf-8")).decode("utf-8", errors="replace")
            return f"🔓 *Base64 Decoded:*\n`{decoded}`"
        elif dec_type == "url":
            decoded = urllib.parse.unquote(text)
            return f"🔓 *URL Decoded:*\n`{decoded}`"
        elif dec_type == "hex":
            decoded = bytes.fromhex(text.replace(" ", "")).decode("utf-8", errors="replace")
            return f"🔓 *Hex Decoded:*\n`{decoded}`"
        else:
            return "⚠️ Supported types: `base64`, `url`, `hex`\nExample: `/decode base64 SGVsbG8gV29ybGQ=`"
    except Exception as e:
        return f"⚠️ Decoding error (check your input): {str(e)}"
