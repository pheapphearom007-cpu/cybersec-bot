import requests
import re

def clean_cve_id(raw_id: str) -> str:
    """Normalize CVE string format, e.g., '2024-3094' -> 'CVE-2024-3094'."""
    raw_id = raw_id.strip().upper()
    if not raw_id.startswith("CVE-"):
        raw_id = f"CVE-{raw_id}"
    return raw_id

def parse_cve_data(data: dict, cve_id: str) -> str:
    """Parse both CVE 5.0 format and legacy CIRCL CVE format."""
    summary = ""
    cvss = "N/A"
    published = "Unknown"
    modified = "Unknown"
    references = []

    # Check CVE 5.0 Schema
    if "containers" in data:
        cna = data.get("containers", {}).get("cna", {})
        cve_meta = data.get("cveMetadata", {})
        
        published = cve_meta.get("datePublished", "Unknown")
        modified = cve_meta.get("dateUpdated", "Unknown")

        # Extract descriptions
        descriptions = cna.get("descriptions", [])
        for d in descriptions:
            if d.get("lang") in ("en", None) and d.get("value"):
                summary = d.get("value")
                break
        if not summary and descriptions:
            summary = descriptions[0].get("value", "")

        # Extract CVSS Metrics
        metrics = cna.get("metrics", [])
        for m in metrics:
            for cvss_key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                if cvss_key in m:
                    cvss = str(m[cvss_key].get("baseScore", "N/A"))
                    break
            if cvss != "N/A":
                break

        # Check ADP (CISA) metrics if CNA metrics didn't have CVSS score
        if cvss == "N/A":
            adp_list = data.get("containers", {}).get("adp", [])
            for adp in adp_list:
                for m in adp.get("metrics", []):
                    for cvss_key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                        if cvss_key in m:
                            cvss = str(m[cvss_key].get("baseScore", "N/A"))
                            break

        # References
        for ref in cna.get("references", []):
            if "url" in ref:
                references.append(ref["url"])

    else:
        # Legacy CIRCL schema
        summary = data.get("summary", "")
        cvss = str(data.get("cvss", "N/A"))
        published = data.get("Published", "Unknown")
        modified = data.get("Modified", "Unknown")
        references = data.get("references", [])

    if not summary:
        summary = "No detailed description provided by the vulnerability authority."

    # Format CVSS severity badge
    severity_label = "📊"
    try:
        score = float(cvss)
        if score >= 9.0:
            severity_label = "🚨 CRITICAL"
        elif score >= 7.0:
            severity_label = "⚠️ HIGH"
        elif score >= 4.0:
            severity_label = "🔶 MEDIUM"
        else:
            severity_label = "🟢 LOW"
    except (ValueError, TypeError):
        severity_label = "📊"

    # Truncate summary if too long for Telegram message limit
    if len(summary) > 650:
        summary = summary[:647] + "..."

    # Format output
    msg = [
        f"🛡️ *Vulnerability Details: {cve_id}*",
        f"━━━━━━━━━━━━━━━━━━",
        f"• *Severity:* {severity_label} ({cvss}/10)",
        f"• *Published:* `{published[:10]}`",
        f"• *Last Updated:* `{modified[:10]}`",
        "",
        f"*Description:*",
        summary,
        "",
        f"🔗 [NVD Official Record](https://nvd.nist.gov/vuln/detail/{cve_id})",
    ]

    if references:
        msg.append(f"🔗 [Technical Advisory]({references[0]})")

    return "\n".join(msg)

def lookup_cve(cve_input: str) -> str:
    """Query CIRCL CVE API for vulnerability intelligence."""
    cve_id = clean_cve_id(cve_input)
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return (
            "⚠️ Invalid CVE ID format.\n"
            "Example format: `/cve CVE-2024-3094` or `/cve 2021-44228`"
        )

    url = f"https://cve.circl.lu/api/cve/{cve_id}"

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 404:
            return f"❌ No vulnerability record found for `{cve_id}`."
        
        response.raise_for_status()
        data = response.json()

        if not data:
            return f"❌ No information found for `{cve_id}`."

        return parse_cve_data(data, cve_id)

    except requests.exceptions.Timeout:
        return "⏳ Request to CVE database timed out. Please try again in a few moments."
    except Exception as e:
        return f"⚠️ Error querying CVE database: {str(e)}"
