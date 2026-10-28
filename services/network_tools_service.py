import ssl
import socket
import datetime
import ipaddress
import requests
import re

PORT_DATABASE = {
    21: ("FTP", "File Transfer Protocol - Often sends credentials in cleartext. Check for anonymous login."),
    22: ("SSH", "Secure Shell - Encrypted remote administration. Watch for brute-force attacks; use key-based auth."),
    23: ("Telnet", "Unencrypted text communications - Highly insecure, vulnerable to eavesdropping and MITM."),
    25: ("SMTP", "Simple Mail Transfer Protocol - Email routing. Watch for open relays and spam abuse."),
    53: ("DNS", "Domain Name System - Vulnerable to DNS amplification, cache poisoning, and zone transfers."),
    80: ("HTTP", "Hypertext Transfer Protocol - Cleartext web traffic. Ensure redirect to HTTPS (Port 443)."),
    88: ("Kerberos", "Authentication protocol used in Active Directory. Target for Kerberoasting / AS-REP Roasting."),
    110: ("POP3", "Post Office Protocol - Email retrieval. Often unencrypted unless using POP3S (Port 995)."),
    123: ("NTP", "Network Time Protocol - Time sync. Often exploited in UDP NTP reflection DDoS attacks."),
    139: ("NetBIOS", "NetBIOS Session Service - Windows file/printer sharing. Risk of SMB enumeration."),
    143: ("IMAP", "Internet Message Access Protocol - Email retrieval. Vulnerable to cleartext snooping without SSL."),
    389: ("LDAP", "Lightweight Directory Access Protocol - Active Directory queries. Look for anonymous binding."),
    443: ("HTTPS", "HTTP over TLS/SSL - Encrypted web traffic. Check for TLS 1.0/1.1 deprecation and weak ciphers."),
    445: ("SMB", "Server Message Block - Windows file sharing. High risk (EternalBlue, WannaCry, SMBGhost)."),
    1433: ("MSSQL", "Microsoft SQL Server - Database port. Target for brute-force and SQL injection."),
    1521: ("Oracle DB", "Oracle Database Listener - Check for default SID names and weak TNS credentials."),
    3306: ("MySQL", "MySQL Database - Ensure remote root login is disabled and bind to localhost/private IP."),
    3389: ("RDP", "Remote Desktop Protocol - Windows remote GUI. High target for ransomware and brute-force (BlueKeep)."),
    5432: ("PostgreSQL", "PostgreSQL Database - Check pg_hba.conf for permissive access."),
    6379: ("Redis", "Redis In-Memory Store - Extremely dangerous if exposed without authentication (RCE risk)."),
    8080: ("HTTP Proxy/Alt", "Common alternative HTTP port, often used by Apache Tomcat, Jenkins, and proxies."),
    8443: ("HTTPS Alt", "Alternative HTTPS port used by management consoles and internal web services."),
    27017: ("MongoDB", "MongoDB NoSQL Database - Frequently targeted if left unauthenticated."),
}

def check_ssl(domain: str) -> str:
    """Inspect SSL/TLS certificate validity and expiration."""
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip()
    if not domain:
        return "⚠️ Usage: `/ssl <domain>`\nExample: `/ssl google.com`"

    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_after_str = cert.get("notAfter", "")

        # Format: 'May 10 12:00:00 2025 GMT'
        expiry_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry_date - datetime.datetime.utcnow()).days

        status_badge = "🟢 Valid" if days_left > 14 else ("🟠 Expiring Soon" if days_left > 0 else "🔴 Expired")

        return (
            f"🔒 *SSL/TLS Certificate: {domain}*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"• *Status:* {status_badge}\n"
            f"• *Days Remaining:* `{days_left} days`\n"
            f"• *Expires On:* `{expiry_date.strftime('%Y-%m-%d %H:%M:%S UTC')}`\n"
            f"• *Issued To:* `{subject.get('commonName', domain)}`\n"
            f"• *Issuer CA:* `{issuer.get('organizationName', issuer.get('commonName', 'Unknown'))}`\n"
        )
    except ssl.SSLCertVerificationError:
        return f"🚨 *SSL Verification Failed for {domain}!*\nThe certificate is self-signed, invalid, or untrusted."
    except Exception as e:
        return f"⚠️ Could not retrieve SSL certificate for `{domain}`: {str(e)}"

def check_headers(target_url: str) -> str:
    """Inspect HTTP response security headers."""
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = f"https://{target_url}"

    try:
        res = requests.get(target_url, timeout=8, allow_redirects=True, headers={"User-Agent": "CyberSecBot/1.0"})
        headers = res.headers

        sec_headers = {
            "Strict-Transport-Security": "HSTS (Enforces HTTPS)",
            "Content-Security-Policy": "CSP (Prevents XSS & data injection)",
            "X-Frame-Options": "Clickjacking Defense",
            "X-Content-Type-Options": "MIME-Sniffing Defense",
            "Referrer-Policy": "Privacy & Referrer Control",
            "Permissions-Policy": "Browser Feature Restrictions",
        }

        found_count = 0
        lines = [
            f"🛡️ *Security Headers: {target_url[:45]}*",
            f"━━━━━━━━━━━━━━━━━━",
        ]

        for header_name, desc in sec_headers.items():
            if header_name in headers:
                found_count += 1
                val = headers[header_name][:60]
                lines.append(f"✅ *{header_name}:*\n   `{val}`")
            else:
                lines.append(f"❌ *{header_name}:* Missing")

        server_header = headers.get("Server", None)
        powered_by = headers.get("X-Powered-By", None)
        if server_header or powered_by:
            lines.append("")
            lines.append(f"ℹ️ *Server Info Leak:* `{server_header or ''} {powered_by or ''}`.strip()")

        score = f"{found_count}/{len(sec_headers)}"
        lines.append(f"\n📊 *Security Score:* `{score} headers implemented`")
        return "\n".join(lines)

    except Exception as e:
        return f"⚠️ Error fetching headers from `{target_url}`: {str(e)}"

def query_dns(domain: str) -> str:
    """Query DNS records via Cloudflare DNS over HTTPS (DoH)."""
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip()
    if not domain:
        return "⚠️ Usage: `/dns <domain>`\nExample: `/dns example.com`"

    record_types = ["A", "AAAA", "MX", "TXT", "NS"]
    lines = [
        f"🌐 *DNS Records for {domain}*",
        f"━━━━━━━━━━━━━━━━━━",
    ]

    try:
        found_any = False
        for r_type in record_types:
            url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={r_type}"
            headers = {"Accept": "application/dns-json"}
            res = requests.get(url, headers=headers, timeout=5).json()

            answers = res.get("Answer", [])
            if answers:
                found_any = True
                vals = [a.get("data", "") for a in answers if "data" in a]
                joined_vals = "\n   • ".join(vals[:4])
                lines.append(f"📌 *{r_type} Records:*\n   • `{joined_vals}`")

        if not found_any:
            return f"❌ No public DNS records found for `{domain}`."

        return "\n\n".join(lines)
    except Exception as e:
        return f"⚠️ Error querying DNS: {str(e)}"

def calculate_cidr(subnet: str) -> str:
    """Calculate IPv4/IPv6 subnet properties."""
    subnet = subnet.strip()
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        return (
            f"🧮 *CIDR Subnet Calculator: `{subnet}`*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"• *Network Address:* `{net.network_address}`\n"
            f"• *Broadcast Address:* `{net.broadcast_address}`\n"
            f"• *Netmask:* `{net.netmask}`\n"
            f"• *Hostmask:* `{net.hostmask}`\n"
            f"• *Total Addresses:* `{net.num_addresses:,}`\n"
            f"• *Usable Host Range:*\n"
            f"  `{net.network_address + 1}` - `{net.broadcast_address - 1}`\n"
        )
    except ValueError as e:
        return f"⚠️ Invalid CIDR format: `{subnet}`.\nExample: `/cidr 192.168.1.0/24` or `/cidr 10.0.0.0/16`"

def port_info(port_num_str: str) -> str:
    """Look up common port usage and security risks."""
    try:
        port = int(port_num_str.strip())
    except ValueError:
        return "⚠️ Usage: `/port <number>`\nExample: `/port 445` or `/port 22`"

    if port in PORT_DATABASE:
        service, security_note = PORT_DATABASE[port]
        return (
            f"🚪 *Port {port} ({service})*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"• *Standard Service:* `{service}`\n"
            f"• *Security & Threat Notes:*\n{security_note}\n\n"
            f"💡 *Tip:* Always verify services using `nmap -sV -p {port} <target>`."
        )
    else:
        return (
            f"🚪 *Port {port}*\n"
            f"• Standard registration: Check IANA registry.\n"
            f"• To inspect live service on a machine: `nmap -sV -p {port} <target>`"
        )
