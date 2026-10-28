CHEATSHEETS = {
    "nmap": (
        "🗺️ *Nmap Port Scanning Cheatsheet*\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "• `nmap -sS -p- <IP>` - Stealth SYN scan all 65,535 ports\n"
        "• `nmap -sV -sC -p <ports> <IP>` - Version detection + Default scripts\n"
        "• `nmap -O <IP>` - OS detection\n"
        "• `nmap -T4 -A -v <IP>` - Aggressive scan (OS, versions, traceroute)\n"
        "• `nmap --script vuln <IP>` - Run vulnerability scanning scripts\n"
        "• `nmap -sn <subnet>` - Ping sweep / host discovery (e.g. 192.168.1.0/24)\n"
    ),
    "linux": (
        "🐧 *Linux Security & Incident Cheatsheet*\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "• `last -a` - View recent logins and remote IP addresses\n"
        "• `tail -f /var/log/auth.log` - Watch SSH/auth attempts (Debian/Ubuntu)\n"
        "• `ss -tulpn` - View all active listening ports and processes\n"
        "• `find / -perm -u=s -type f 2>/dev/null` - Find all SUID binaries\n"
        "• `crontab -l` & `ls -la /etc/cron*` - Inspect scheduled persistence jobs\n"
        "• `ps aux --sort=-%cpu | head -n 10` - Top CPU processes (cryptominers)\n"
    ),
    "wireshark": (
        "🦈 *Wireshark Display Filters Cheatsheet*\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "• `http.request.method == \"POST\"` - Show all HTTP POST requests\n"
        "• `dns.flags.response == 0` - Filter DNS queries only\n"
        "• `tcp.flags.reset == 1` - Identify TCP RST packets (abrupt terminations)\n"
        "• `ip.addr == 192.168.1.5` - Filter all traffic to/from an IP\n"
        "• `tls.handshake.type == 1` - Filter TLS Client Hello packets\n"
        "• `frame contains \"password\"` - Search unencrypted credentials in packet payload\n"
    ),
    "owasp": (
        "🛡️ *OWASP Top 10 Web Vulnerabilities*\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "1. *A01: Broken Access Control* - Unauthorized user elevation/access\n"
        "2. *A02: Cryptographic Failures* - Weak ciphers, cleartext transmission\n"
        "3. *A03: Injection* - SQLi, Command Injection, LDAP injection\n"
        "4. *A04: Insecure Design* - Missing security architecture patterns\n"
        "5. *A05: Security Misconfiguration* - Default passwords, debug enabled\n"
        "6. *A06: Vulnerable Components* - Outdated dependencies & libraries\n"
        "7. *A07: Identification & Auth Failures* - Weak session/MFA tokens\n"
        "8. *A08: Software & Data Integrity Failures* - Untrusted CI/CD pipelines\n"
        "9. *A09: Security Logging & Monitoring Failures* - Blind to breaches\n"
        "10. *A10: Server-Side Request Forgery (SSRF)* - Inducing server to fetch URLs\n"
    ),
}

def get_cheatsheet(topic: str = "") -> str:
    """Retrieve security cheat sheet by topic."""
    topic = topic.lower().strip()
    if topic in CHEATSHEETS:
        return CHEATSHEETS[topic]

    available = ", ".join([f"`{k}`" for k in CHEATSHEETS.keys()])
    return (
        f"📖 *Security Cheatsheet Library*\n"
        f"Available topics: {available}\n\n"
        f"Usage: `/cheat <topic>`\n"
        f"Example: `/cheat nmap` or `/cheat linux`"
    )
