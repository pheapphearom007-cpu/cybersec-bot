import requests
import re
import datetime
import urllib.parse
from services.ip_service import lookup_ip

def check_email_security(domain: str) -> str:
    """Audit SPF and DMARC DNS records for spoofing vulnerability."""
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip()
    if not domain:
        return "⚠️ Usage: `/dmarc <domain>`\nExample: `/dmarc paypal.com`"

    headers = {"Accept": "application/dns-json"}
    
    # Check SPF record
    spf_record = None
    try:
        r_spf = requests.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT", headers=headers, timeout=5).json()
        for ans in r_spf.get("Answer", []):
            data = ans.get("data", "").strip('"')
            if data.startswith("v=spf1"):
                spf_record = data
                break
    except Exception:
        pass

    # Check DMARC record
    dmarc_record = None
    try:
        r_dmarc = requests.get(f"https://cloudflare-dns.com/dns-query?name=_dmarc.{domain}&type=TXT", headers=headers, timeout=5).json()
        for ans in r_dmarc.get("Answer", []):
            data = ans.get("data", "").strip('"')
            if data.startswith("v=DMARC1"):
                dmarc_record = data
                break
    except Exception:
        pass

    # Analyze risk
    vulnerabilities = []
    dmarc_policy = "None"
    
    if dmarc_record:
        p_match = re.search(r"p=([a-zA-Z]+)", dmarc_record)
        if p_match:
            dmarc_policy = p_match.group(1).lower()

    if not spf_record:
        vulnerabilities.append("❌ Missing SPF Record")
    elif "+all" in spf_record:
        vulnerabilities.append("🚨 SPF allows all senders (+all)")
    elif "?all" in spf_record:
        vulnerabilities.append("⚠️ Neutral SPF (?all) does not block unauthorized senders")

    if not dmarc_record:
        vulnerabilities.append("❌ Missing DMARC Record")
    elif dmarc_policy == "none":
        vulnerabilities.append("⚠️ DMARC policy is 'none' (Monitoring only; spoofed emails are NOT rejected)")

    if not vulnerabilities:
        verdict = "🟢 *SECURE:* Strong protection against domain impersonation."
    elif dmarc_policy in ("quarantine", "reject"):
        verdict = "🟡 *MODERATE:* DMARC enforcement active with minor SPF caveats."
    else:
        verdict = "🔴 *HIGH RISK:* Domain is vulnerable to email spoofing & phishing!"

    lines = [
        f"📧 *Email Spoofing Audit: {domain}*",
        f"━━━━━━━━━━━━━━━━━━",
        f"• *SPF Record:*",
        f"  `{spf_record if spf_record else 'NOT FOUND'}`",
        "",
        f"• *DMARC Record:*",
        f"  `{dmarc_record if dmarc_record else 'NOT FOUND'}`",
        f"• *DMARC Policy:* `{dmarc_policy.upper()}`",
        "",
        f"*Security Assessment:*",
        verdict,
    ]
    if vulnerabilities:
        lines.append("\n*Identified Issues:*")
        for v in vulnerabilities:
            lines.append(f"• {v}")

    return "\n".join(lines)

def expand_short_url(short_url: str) -> str:
    """Follow HTTP redirect chain to uncover the real destination URL."""
    short_url = short_url.strip()
    if not short_url.startswith("http://") and not short_url.startswith("https://"):
        short_url = f"https://{short_url}"

    try:
        session = requests.Session()
        res = session.get(short_url, timeout=10, allow_redirects=True, headers={"User-Agent": "CyberSecBot/1.0"})
        
        history = res.history
        lines = [
            f"🔗 *URL Redirection Tracer*",
            f"━━━━━━━━━━━━━━━━━━",
            f"• *Initial Link:* `{short_url}`",
        ]

        if history:
            lines.append(f"• *Redirect Hops ({len(history)}):*")
            for idx, hop in enumerate(history, 1):
                lines.append(f"  {idx}. `{hop.url}` `({hop.status_code})`")
        else:
            lines.append("• *Redirects:* None (Direct URL)")

        final_url = res.url
        lines.append(f"\n🎯 *Final Destination:*\n`{final_url}`")
        lines.append(f"\n🔍 [Scan on VirusTotal](https://www.virustotal.com/gui/search/{urllib.parse.quote(final_url, safe='')})")
        return "\n".join(lines)

    except Exception as e:
        return f"⚠️ Error expanding URL: {str(e)}"

def get_cisa_zero_days(limit: int = 4) -> str:
    """Fetch latest actively exploited zero-days from CISA KEV catalog."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url, timeout=10)
        data = res.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return "⚠️ Could not retrieve CISA KEV data."

        total = data.get("count", len(vulns))
        # Vulns are sorted chronologically with newest at the top
        recent = vulns[:limit]

        lines = [
            f"🚨 *CISA Actively Exploited Zero-Days (KEV)*",
            f"Total Cataloged Threats: `{total}`\n",
        ]

        for v in recent:
            cve_id = v.get("cveID")
            vendor = v.get("vendorProject")
            product = v.get("product")
            name = v.get("vulnerabilityName")
            date_added = v.get("dateAdded")
            due_date = v.get("dueDate", "Immediate")
            desc = v.get("shortDescription", "")
            if len(desc) > 130:
                desc = desc[:127] + "..."

            lines.append(
                f"• *[{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})* — *{vendor} {product}*\n"
                f"  _{name}_\n"
                f"  📅 *Added:* `{date_added}` | ⏰ *Patch Due:* `{due_date}`\n"
                f"  _{desc}_\n"
            )

        lines.append("💡 *Note:* These vulnerabilities have verified active in-the-wild exploitation.")
        return "\n".join(lines)
    except Exception as e:
        return f"⚠️ Error querying CISA feed: {str(e)}"

def analyze_ioc(indicator: str) -> str:
    """Universal IoC analyzer: auto-identifies Hash, IP, or Domain."""
    ind = indicator.strip()
    
    # 1. MD5 Hash (32 hex characters)
    if re.fullmatch(r"^[a-fA-F0-9]{32}$", ind):
        return (
            f"🔑 *IoC Classification: MD5 File Hash*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"• *Hash:* `{ind}`\n"
            f"• *Length:* 32 hex chars (128-bit)\n\n"
            f"🔗 [VirusTotal Hash Search](https://www.virustotal.com/gui/file/{ind})\n"
            f"🔗 [MalwareBazaar Lookup](https://bazaar.abuse.ch/sample/{ind}/)"
        )

    # 2. SHA-1 Hash (40 hex characters)
    if re.fullmatch(r"^[a-fA-F0-9]{40}$", ind):
        return (
            f"🔑 *IoC Classification: SHA-1 File Hash*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"• *Hash:* `{ind}`\n"
            f"• *Length:* 40 hex chars (160-bit)\n\n"
            f"🔗 [VirusTotal Hash Search](https://www.virustotal.com/gui/file/{ind})"
        )

    # 3. SHA-256 Hash (64 hex characters)
    if re.fullmatch(r"^[a-fA-F0-9]{64}$", ind):
        return (
            f"🔑 *IoC Classification: SHA-256 File Hash*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"• *Hash:* `{ind}`\n"
            f"• *Length:* 64 hex chars (256-bit)\n\n"
            f"🔗 [VirusTotal Hash Search](https://www.virustotal.com/gui/file/{ind})\n"
            f"🔗 [MalwareBazaar Lookup](https://bazaar.abuse.ch/sample/{ind}/)"
        )

    # 4. IPv4 Address
    if re.fullmatch(r"^(\d{1,3}\.){3}\d{1,3}$", ind):
        return lookup_ip(ind)

    # 5. Domain Name
    domain_match = re.sub(r"^https?://", "", ind).split("/")[0]
    if "." in domain_match and not domain_match.endswith("."):
        return (
            f"🌐 *IoC Classification: Domain / Hostname*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"• *Domain:* `{domain_match}`\n\n"
            f"🔗 [VirusTotal Domain Report](https://www.virustotal.com/gui/domain/{domain_match})\n"
            f"🔗 [AlienVault OTX Pulse](https://otx.alienvault.com/indicator/domain/{domain_match})\n"
            f"🔗 [URLhaus Malware Reports](https://urlhaus.abuse.ch/browse.php?search={domain_match})\n\n"
            f"💡 *Commands:* Use `/whois {domain_match}` or `/dns {domain_match}` for deeper recon."
        )

    return (
        "⚠️ Unrecognized indicator format.\n"
        "Supported IoCs: MD5, SHA-1, SHA-256 hashes, IPv4 addresses, or Domains."
    )

def convert_epoch(epoch_str: str) -> str:
    """Convert Unix epoch timestamp (seconds or milliseconds) to human date."""
    epoch_str = epoch_str.strip()
    if epoch_str.lower() == "now":
        now_ts = int(datetime.datetime.utcnow().timestamp())
        now_utc = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"⏱️ *Current Unix Epoch:* `{now_ts}`\n• *UTC Time:* `{now_utc}`"

    try:
        val = float(epoch_str)
        # If timestamp is in milliseconds (>= 100000000000)
        if val > 100000000000:
            val = val / 1000.0

        dt_utc = datetime.datetime.utcfromtimestamp(val)
        return (
            f"⏱️ *Unix Timestamp Conversion*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"• *Input Epoch:* `{epoch_str}`\n"
            f"• *UTC Time:* `{dt_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}`\n"
            f"• *ISO 8601:* `{dt_utc.isoformat()}Z`\n"
            f"• *Relative:* {dt_utc.strftime('%A, %B %d, %Y')}"
        )
    except Exception:
        return (
            "⚠️ Invalid timestamp format.\n"
            "Example: `/epoch 1711728000` or `/epoch now`"
        )
