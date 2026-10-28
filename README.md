# 🛡️ CyberSec Telegram Bot (@phirom007_bot)

A powerful, all-in-one Telegram bot designed for cybersecurity practitioners, students, and enthusiasts. Features live threat intelligence, CISA zero-days, vulnerability lookups, email spoofing audits, URL expanders, network reconnaissance, file attachment hashing, cryptography tools, technical mock interviews, and AI-powered Q&A.

---

## ⚡ Complete Command Reference

### 🚨 1. Threat Intelligence & Zero-Days
| Command | Description | Example |
| :--- | :--- | :--- |
| `/news` | Fetch breaking cyber news from The Hacker News | `/news` |
| `/cisa` | Check CISA actively exploited zero-days (KEV catalog) | `/cisa` |
| `/cve <ID>` | Check CVSS severity, description & advisories | `/cve CVE-2024-3094` |
| `/ioc <target>` | Universal IoC scanner (hashes, IPs, domains) | `/ioc 44d88612fea8a8f36de82e1278abb02f` |
| `/pwned <email>` | Check if an email appeared in known data breaches | `/pwned user@example.com` |

### 📧 2. Phishing & Email Defense
| Command | Description | Example |
| :--- | :--- | :--- |
| `/dmarc <domain>` | Audit SPF & DMARC records for email spoofing vulnerability | `/dmarc paypal.com` |
| `/expand <url>` | Unshorten redirect links (bit.ly, tinyurl) without clicking | `/expand https://bit.ly/3xyz` |
| `/defang <link>` | Convert dangerous links to safe defanged format | `/defang https://malicious.com` |
| `/refang <link>` | Restore defanged indicator to operational format | `/refang hxxps[://]evil[.]com` |

### 🌐 3. Reconnaissance & Network OSINT
| Command | Description | Example |
| :--- | :--- | :--- |
| `/ip <target>` | Check IP threat info, ISP, ASN & Proxy status | `/ip 1.1.1.1` |
| `/whois <domain>` | Check domain registration date, registrar & expiry | `/whois github.com` |
| `/subdomains <domain>` | Enumerate active public subdomains | `/subdomains github.com` |
| `/ssl <domain>` | Check SSL/TLS certificate validity & expiration | `/ssl google.com` |
| `/headers <url>` | Audit HTTP response security headers (HSTS, CSP, etc.) | `/headers github.com` |
| `/dns <domain>` | Query DNS records (A, MX, TXT, NS) via Cloudflare DoH | `/dns cloudflare.com` |
| `/port <number>` | Look up common port usage and exploit risks | `/port 445` |
| `/cidr <subnet>` | Subnet calculator (netmask, host count, usable range) | `/cidr 192.168.1.0/24` |
| `/mac <address>` | Lookup hardware vendor by MAC address | `/mac 00:1A:2B:3C:4D:5E` |
| `/useragent <str>` | Parse and analyze browser User-Agent strings | `/useragent sqlmap/1.5` |

### 🕵️ 4. SOC Analyst & File Inspection
| Command | Description | Example |
| :--- | :--- | :--- |
| `/epoch <ts>` | Convert Unix epoch timestamps (seconds/ms) to UTC | `/epoch 1711728000` |
| **Send Any File** | Drop any file into chat to get MD5, SHA-256 & VirusTotal links | *(Send file directly)* |

### 🔐 5. Cryptography & Password Tools
| Command | Description | Example |
| :--- | :--- | :--- |
| `/genpass [len]` | Generate a cryptographically secure random password | `/genpass 20` |
| `/checkpass <pwd>` | Analyze password entropy, strength & complexity | `/checkpass P@ssw0rd123` |
| `/hash <text>` | Calculate MD5, SHA-1, SHA-256, and SHA-512 hashes | `/hash admin` |
| `/encode <type> <txt>` | Encode string to `base64`, `url`, or `hex` | `/encode base64 Hello` |
| `/decode <type> <txt>` | Decode string from `base64`, `url`, or `hex` | `/decode base64 SGVsbG8=` |
| `/rot13 <text>` | Encode/Decode ROT13 cipher | `/rot13 cvat` |
| `/caesar <shift> <txt>`| Caesar cipher with custom shift (+/-) | `/caesar 3 Attack at dawn` |

### 💼 6. Career, Learning & Automation
| Command | Description | Example |
| :--- | :--- | :--- |
| `/ask <question>` | Ask AI any cybersecurity question or concept | `/ask What is a buffer overflow?` |
| `/quiz` | Interactive cybersecurity trivia quiz with buttons | `/quiz` |
| `/interview [role]` | Mock technical interview questions with revealable answers | `/interview soc` |
| `/roadmap [path]` | Career roadmaps for SOC, PenTesting, and Cloud Security | `/roadmap pentest` |
| `/subscribe` | Subscribe to automated daily morning threat briefing | `/subscribe` |
| `/unsubscribe` | Unsubscribe from daily briefings | `/unsubscribe` |
| `/briefing` | Manually generate threat briefing right now | `/briefing` |
| `/cheat [topic]` | Security cheatsheets (nmap, linux, wireshark, owasp) | `/cheat nmap` |

---

## 🛠️ Service Management

The bot runs 24/7 as a background Linux service:

- **Check status:** `systemctl --user status cybersec-bot`
- **Restart bot:** `systemctl --user restart cybersec-bot`
- **Stop bot:** `systemctl --user stop cybersec-bot`
- **View live logs:** `journalctl --user -u cybersec-bot -f`
