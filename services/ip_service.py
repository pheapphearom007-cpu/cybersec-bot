import requests
import re

def is_valid_ip_or_domain(target: str) -> bool:
    """Validate IP address or simple domain name."""
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(ip_pattern, target) or re.match(domain_pattern, target))

def lookup_ip(target: str) -> str:
    """Lookup IP or domain information (ISP, Country, ASN, Hosting/Proxy flag)."""
    target = target.strip()
    if not is_valid_ip_or_domain(target):
        return (
            "⚠️ Invalid IP address or domain.\n"
            "Usage: `/ip <ip_or_domain>`\n"
            "Example: `/ip 8.8.8.8` or `/ip cloudflare.com`"
        )

    url = f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting"
    
    try:
        response = requests.get(url, timeout=8)
        data = response.json()

        if data.get("status") != "success":
            return f"❌ Lookup failed: {data.get('message', 'Target not found')}"

        query = data.get("query", target)
        country = data.get("country", "Unknown")
        city = data.get("city", "Unknown")
        isp = data.get("isp", "Unknown")
        org = data.get("org", "Unknown")
        as_num = data.get("as", "Unknown")
        hosting = "Yes ⚠️ (Datacenter/Cloud)" if data.get("hosting") else "No (Residential/Business)"
        proxy = "Yes 🚨 (VPN/Tor/Proxy detected)" if data.get("proxy") else "No"

        msg = [
            f"🌐 *Network Intelligence for `{query}`*",
            f"━━━━━━━━━━━━━━━━━━",
            f"• *Country/City:* {country}, {city}",
            f"• *ISP:* {isp}",
            f"• *Organization:* {org}",
            f"• *ASN:* `{as_num}`",
            f"• *Hosting Provider:* {hosting}",
            f"• *Proxy / VPN / Tor:* {proxy}",
            "",
            f"🔗 [VirusTotal Search](https://www.virustotal.com/gui/ip-address/{query})",
        ]
        return "\n".join(msg)

    except requests.exceptions.Timeout:
        return "⏳ Request timed out. Please try again."
    except Exception as e:
        return f"⚠️ Error looking up IP: {str(e)}"
