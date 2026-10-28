import secrets

INTERVIEW_QUESTIONS = {
    "soc": [
        {
            "q": "A user reports an unexpected MFA push prompt while they were asleep. What are your initial triage and containment steps?",
            "a": (
                "*SOC Analyst Model Answer:*\n"
                "1. **Identify & Validate:** Contact the user via out-of-band channel (phone) to verify they did not trigger it.\n"
                "2. **Containment:** Immediately revoke active user sessions and reset their credentials to prevent MFA fatigue acceptance.\n"
                "3. **Investigate Logs:** Check IdP (Entra ID/Okta) logs for the source IP, user-agent, geolocation, and whether any sign-in succeeded.\n"
                "4. **Scope:** Check if the source IP attempted logins on other company accounts.\n"
                "5. **Remediation:** Enforce number-matching MFA or FIDO2 keys to eliminate push fatigue vulnerability."
            ),
        },
        {
            "q": "What is the difference between a True Positive and a False Positive in SIEM alert triage?",
            "a": (
                "*SOC Analyst Model Answer:*\n"
                "• **True Positive:** The alert fired on actual malicious or unauthorized activity (e.g. real Mimikatz execution).\n"
                "• **False Positive:** The alert fired on benign/legitimate activity that triggered a signature (e.g. an admin running PowerShell backup script that triggered a generic suspicious script rule).\n\n"
                "*Key Action:* False positives should be tuned with strict exclusion criteria to reduce alert fatigue without blinding detection."
            ),
        },
    ],
    "pentest": [
        {
            "q": "How does Blind SQL Injection differ from Inband (Classic) SQL Injection, and how do you exploit it?",
            "a": (
                "*Penetration Tester Model Answer:*\n"
                "• **Inband (Classic):** The web application reflects the database query output directly in the HTML response (e.g. `UNION SELECT username, password FROM users`).\n"
                "• **Blind SQLi:** The application does NOT return database records in the response. It comes in two flavors:\n"
                "   1. *Boolean-based:* Injecting conditions (e.g. `AND 1=1` vs `AND 1=2`) and observing differences in page content/status code.\n"
                "   2. *Time-based:* Injecting delay functions (e.g. `WAITFOR DELAY '0:0:5'` or `pg_sleep(5)`) and measuring response latency.\n"
                "• **Remediation:** Parameterized queries (Prepared Statements)."
            ),
        },
        {
            "q": "What is Kerberoasting and how does an attacker execute it inside Active Directory?",
            "a": (
                "*Penetration Tester Model Answer:*\n"
                "Kerberoasting is a post-exploitation attack targeting Service Principal Names (SPNs):\n"
                "1. Any valid domain user requests a Kerberos Ticket Granting Service (TGS) ticket for an SPN service account.\n"
                "2. The Domain Controller encrypts the TGS ticket using the NTLM hash of the service account's password.\n"
                "3. The attacker extracts the ticket from memory and cracks the hash offline using Hashcat (`hashcat -m 13100`) without triggering domain lockouts.\n"
                "• **Defense:** Use Group Managed Service Accounts (gMSA) with 120-character random passwords."
            ),
        },
    ],
    "cloud": [
        {
            "q": "What is the principle of least privilege in AWS IAM, and how can an overly permissive role lead to privilege escalation?",
            "a": (
                "*Cloud Security Model Answer:*\n"
                "• **Least Privilege:** Granting only the exact permissions needed to perform a specific task, and nothing more.\n"
                "• **Privilege Escalation Risk:** If an IAM user/role has permissions like `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, or `lambda:UpdateFunctionCode`, an attacker can modify policies to attach `AdministratorAccess` to their own identity.\n"
                "• **Defense:** Use IAM Access Advisor, SCPs (Service Control Policies), and IAM Permission Boundaries."
            ),
        },
    ],
}

ROADMAPS = {
    "soc": (
        "🛡️ *Cybersecurity Roadmap: SOC Analyst (Blue Team)*\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "1. *Foundations:* Networking (TCP/IP, OSI model, DNS, HTTP/S, subnets), Linux/Windows CLI.\n"
        "2. *Security Fundamentals:* Security+, OWASP Top 10, MITRE ATT&CK framework.\n"
        "3. *SIEM & Log Analysis:* Splunk (Boss of the SOC), ELK Stack, Wireshark, Sysmon.\n"
        "4. *Incident Response:* Malware analysis basics, Cyber Kill Chain, memory forensics (Volatility).\n"
        "5. *Recommended Practice:* TryHackMe (SOC Level 1 path), LetsDefend, CyberDefenders.\n"
        "6. *Certifications:* CompTIA Security+, BTL1 (Blue Team Level 1), SC-200."
    ),
    "pentest": (
        "⚔️ *Cybersecurity Roadmap: Ethical Hacker / PenTester (Red Team)*\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "1. *Foundations:* Linux power user, scripting (Python, Bash, PowerShell), networking protocols.\n"
        "2. *Web Security:* Burp Suite, SQLi, XSS, CSRF, SSRF, IDOR, API security.\n"
        "3. *Network & Active Directory Pentesting:* Nmap, Metasploit, BloodHound, Kerberoasting, Mimikatz.\n"
        "4. *Privilege Escalation:* SUID, cronjobs, kernel exploits, Windows token impersonation.\n"
        "5. *Recommended Practice:* HackTheBox, PortSwigger Web Security Academy (Free!), TryHackMe.\n"
        "6. *Certifications:* eJPT, PNPT (Practical Network Penetration Tester), OSCP."
    ),
    "cloud": (
        "☁️ *Cybersecurity Roadmap: Cloud Security Engineer*\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "1. *Foundations:* Cloud architecture (AWS, Azure, or GCP), Linux, Docker, Kubernetes.\n"
        "2. *IAM & Architecture:* Zero Trust architecture, Least privilege, Secrets management (Vault, KMS).\n"
        "3. *Cloud Posture & Detection:* CSPM tools (Wiz, Prisma), GuardDuty, CloudTrail, Sentinel.\n"
        "4. *Infrastructure as Code (IaC) Security:* Terraform security, Checkov, Trivy.\n"
        "5. *Certifications:* AWS Certified Security Specialty, Azure Security Engineer (AZ-500), CCSP."
    ),
}

def get_random_interview(role: str = "soc"):
    """Get random interview question by role."""
    role = role.lower().strip()
    if role not in INTERVIEW_QUESTIONS:
        role = "soc"
    return secrets.choice(INTERVIEW_QUESTIONS[role])

def get_roadmap(path: str = "soc") -> str:
    """Get career roadmap."""
    path = path.lower().strip()
    if path in ROADMAPS:
        return ROADMAPS[path]
    available = ", ".join([f"`{k}`" for k in ROADMAPS.keys()])
    return (
        f"🧭 *Cybersecurity Career Paths*\n"
        f"Available roadmaps: {available}\n\n"
        f"Usage: `/roadmap [soc|pentest|cloud]`\n"
        f"Example: `/roadmap soc` or `/roadmap pentest`"
    )
