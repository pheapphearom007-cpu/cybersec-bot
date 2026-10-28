import requests
import re

def lookup_whois(domain: str) -> str:
    """Lookup WHOIS / Registration data using ICANN RDAP."""
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip()
    if not domain:
        return "⚠️ Usage: `/whois <domain>`\nExample: `/whois github.com`"

    url = f"https://rdap.org/domain/{domain}"
    try:
        res = requests.get(url, timeout=7)
        if res.status_code == 404:
            return f"❌ No registration records found for `{domain}`."
        res.raise_for_status()
        data = res.json()

        handle = data.get("handle", domain)
        status_list = data.get("status", [])
        events = data.get("events", [])
        
        created = "Unknown"
        expires = "Unknown"
        updated = "Unknown"

        for event in events:
            action = event.get("eventAction")
            date = event.get("eventDate", "")[:10]
            if action == "registration":
                created = date
            elif action == "expiration":
                expires = date
            elif action == "last changed":
                updated = date

        # Find registrar entity
        registrar = "Unknown"
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for prop in vcard[1]:
                        if prop[0] == "fn":
                            registrar = prop[3]
                            break

        nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]

        lines = [
            f"📋 *WHOIS / RDAP Record: {domain}*",
            f"━━━━━━━━━━━━━━━━━━",
            f"• *Registrar:* `{registrar}`",
            f"• *Registered On:* `{created}`",
            f"• *Expires On:* `{expires}`",
            f"• *Last Updated:* `{updated}`",
        ]
        if status_list:
            lines.append(f"• *Domain Status:* `{status_list[0]}`")
        if nameservers:
            lines.append(f"• *Nameservers:*\n   `{', '.join(nameservers[:3])}`")

        return "\n".join(lines)

    except Exception as e:
        return f"⚠️ Could not retrieve WHOIS data for `{domain}`: {str(e)}"

def find_subdomains(domain: str) -> str:
    """Find public subdomains of a domain."""
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip()
    if not domain:
        return "⚠️ Usage: `/subdomains <domain>`\nExample: `/subdomains github.com`"

    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        res = requests.get(url, timeout=10)
        text = res.text.strip()
        if not text or "error" in text.lower():
            return f"❌ No subdomains found or API rate limit reached for `{domain}`."

        entries = text.splitlines()[:15]
        lines = [
            f"🔎 *Subdomains for `{domain}` ({len(entries)} results)*",
            f"━━━━━━━━━━━━━━━━━━",
        ]
        for item in entries:
            parts = item.split(",")
            sub = parts[0]
            ip = parts[1] if len(parts) > 1 else ""
            lines.append(f"• `{sub}` `({ip})`")

        return "\n".join(lines)
    except Exception as e:
        return f"⚠️ Error searching subdomains: {str(e)}"

def lookup_mac(mac: str) -> str:
    """Look up hardware vendor from MAC address OUI."""
    mac_clean = re.sub(r"[^a-fA-F0-9]", "", mac).upper()
    if len(mac_clean) < 6:
        return "⚠️ Invalid MAC address format.\nExample: `/mac 00:1A:2B:3C:4D:5E` or `/mac 001A2B`"

    oui = ":".join([mac_clean[i:i+2] for i in range(0, min(len(mac_clean), 12), 2)])
    url = f"https://api.macvendors.com/{oui}"
    try:
        res = requests.get(url, timeout=6)
        if res.status_code == 404:
            return f"❌ No vendor registered for OUI `{oui[:8]}`."
        vendor = res.text.strip()
        return (
            f"📟 *MAC Vendor Lookup: `{oui}`*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"• *Manufacturer:* `{vendor}`\n"
            f"• *OUI Prefix:* `{oui[:8]}`"
        )
    except Exception as e:
        return f"⚠️ Error looking up MAC address: {str(e)}"

def check_breach(email: str) -> str:
    """Check if email appeared in public data breaches via XposedOrNot."""
    email = email.strip()
    if "@" not in email or "." not in email:
        return "⚠️ Please provide a valid email.\nExample: `/pwned user@example.com`"

    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        res = requests.get(url, timeout=7)
        if res.status_code == 404:
            return (
                f"🛡️ *Good news! No breaches found for:* `{email}`\n\n"
                f"This email was not detected in known public data leaks."
            )
        data = res.json()
        breaches = data.get("breaches", [])
        if not breaches:
            return f"🟢 No breach records found for `{email}`."

        # Flatten list if nested
        flat_breaches = []
        for b in breaches:
            if isinstance(b, list):
                flat_breaches.extend(b)
            else:
                flat_breaches.append(b)

        count = len(flat_breaches)
        sample = flat_breaches[:10]
        joined = "\n• ".join([f"`{name}`" for name in sample])

        return (
            f"🚨 *BREACH ALERT: {email}*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"⚠️ Found in *{count}* known data breaches!\n\n"
            f"*Breach Sources:*\n• {joined}\n\n"
            f"🛡️ *Recommended Action:* Change passwords immediately and enable Multi-Factor Authentication (MFA)."
        )
    except Exception as e:
        return f"⚠️ Error checking breach database: {str(e)}"

def parse_useragent(ua: str) -> str:
    """Analyze User-Agent string for browser, OS, device, and bot traits."""
    if not ua:
        return "⚠️ Usage: `/useragent <string>`"

    ua_lower = ua.lower()

    # Detect Bot / Crawler
    is_bot = any(bot_id in ua_lower for bot_id in ["bot", "crawler", "spider", "scraper", "curl", "python", "wget", "nmap", "sqlmap", "nikto", "gobuster"])

    # Detect OS
    os_name = "Unknown OS"
    if "windows nt 10.0" in ua_lower: os_name = "Windows 10/11"
    elif "windows" in ua_lower: os_name = "Windows"
    elif "android" in ua_lower: os_name = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower: os_name = "Apple iOS"
    elif "mac os x" in ua_lower: os_name = "macOS"
    elif "linux" in ua_lower: os_name = "Linux"

    # Detect Browser / Client
    browser = "Unknown Client"
    if "edg/" in ua_lower: browser = "Microsoft Edge"
    elif "chrome/" in ua_lower: browser = "Google Chrome"
    elif "firefox/" in ua_lower: browser = "Mozilla Firefox"
    elif "safari/" in ua_lower and "chrome" not in ua_lower: browser = "Apple Safari"
    elif "curl" in ua_lower: browser = "cURL Command-Line Tool"
    elif "python-requests" in ua_lower: browser = "Python Requests"
    elif "sqlmap" in ua_lower: browser = "SQLMap (Attack Tool ⚠️)"
    elif "nmap" in ua_lower: browser = "Nmap Scanner (Recon Tool ⚠️)"

    badge = "🚨 Suspicious / Automated Tool" if is_bot else "🟢 Standard User Browser"

    return (
        f"🕵️ *User-Agent Analysis*\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"• *Classification:* {badge}\n"
        f"• *Detected OS:* `{os_name}`\n"
        f"• *Detected Client:* `{browser}`\n"
        f"• *Automated Bot/Scanner:* `{'Yes ⚠️' if is_bot else 'No'}`\n\n"
        f"*Raw String:*\n`{ua[:150]}`"
    )
