from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes

from services.news_service import get_latest_news
from services.cve_service import lookup_cve
from services.ip_service import lookup_ip
from services.ai_service import ask_cyber_ai
from services.crypto_service import (
    generate_password,
    check_password_strength,
    compute_hashes,
    encode_text,
    decode_text,
)
from services.network_tools_service import (
    check_ssl,
    check_headers,
    query_dns,
    calculate_cidr,
    port_info,
)
from services.cheatsheet_service import get_cheatsheet
from services.osint_service import (
    lookup_whois,
    find_subdomains,
    lookup_mac,
    check_breach,
    parse_useragent,
)
from services.ctf_service import (
    rot13,
    caesar_cipher,
    defang_indicator,
    refang_indicator,
    get_random_quiz,
)
from services.threat_service import (
    check_email_security,
    expand_short_url,
    get_cisa_zero_days,
    analyze_ioc,
    convert_epoch,
)
from services.career_service import (
    get_random_interview,
    get_roadmap,
)
from services.subscription_service import (
    subscribe_chat,
    unsubscribe_chat,
    build_daily_briefing,
)

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message and interactive menu."""
    welcome_text = (
        "🛡️ *Welcome to CyberSec Bot (@phirom007_bot)*\n"
        "Your Swiss Army Knife for Cybersecurity, Recon & Intelligence.\n\n"
        "🗂️ *Commands by Category:*\n\n"
        "🚨 *Threat Intel & Zero-Days:*\n"
        "• `/news` - Latest security news\n"
        "• `/cisa` - CISA actively exploited zero-days\n"
        "• `/cve <ID>` - Lookup CVE vulnerability\n"
        "• `/ioc <target>` - Universal IoC reputation check\n"
        "• `/pwned <email>` - Check data breaches\n\n"
        "📧 *Phishing & Email Defense:*\n"
        "• `/dmarc <domain>` - Email spoofing & SPF/DMARC audit\n"
        "• `/expand <url>` - Unshorten redirect links (bit.ly...)\n"
        "• `/defang <link>` - Sanitize malicious links\n"
        "• `/refang <link>` - Restore defanged links\n\n"
        "🌐 *Recon & Network OSINT:*\n"
        "• `/whois <domain>` - Domain registration & expiry\n"
        "• `/subdomains <domain>` - Find active subdomains\n"
        "• `/ip <target>` - IP threat info, ISP & ASN\n"
        "• `/ssl <domain>` - SSL/TLS certificate expiry\n"
        "• `/headers <url>` - Security headers audit\n"
        "• `/dns <domain>` - DNS-over-HTTPS records\n"
        "• `/port <number>` - Port & exploit reference\n"
        "• `/cidr <subnet>` - Subnet calculator\n"
        "• `/mac <address>` - Hardware vendor lookup\n"
        "• `/useragent <str>` - User-Agent analyzer\n\n"
        "🕵️ *SOC & Incident Response:*\n"
        "• `/epoch <ts>` - Convert Unix timestamp to UTC\n"
        "• _Send Any File:_ Bot calculates MD5 & SHA-256!\n\n"
        "🔐 *Cryptography & Passwords:*\n"
        "• `/genpass [len]` - Generate secure password\n"
        "• `/checkpass <pwd>` - Password strength analyzer\n"
        "• `/hash <text>` - MD5, SHA-1, SHA-256, SHA-512\n"
        "• `/encode` & `/decode` - Base64, URL, Hex\n"
        "• `/rot13` & `/caesar` - CTF ciphers\n\n"
        "💼 *Career, Quiz & Automated Alerts:*\n"
        "• `/interview [role]` - Technical interview questions\n"
        "• `/roadmap [path]` - Career guides (soc/pentest/cloud)\n"
        "• `/quiz` - Test your cybersecurity knowledge\n"
        "• `/subscribe` - Receive daily morning threat briefing\n"
        "• `/unsubscribe` - Stop daily briefings\n"
        "• `/cheat [topic]` - Cheatsheets (nmap, linux, owasp)\n"
        "• `/ask <question>` - Ask CyberSec AI\n"
    )

    keyboard = [
        [
            InlineKeyboardButton("🚨 CISA Zero-Days", callback_data="btn_cisa"),
            InlineKeyboardButton("📰 Top News", callback_data="btn_news"),
        ],
        [
            InlineKeyboardButton("🎯 Quick Quiz", callback_data="btn_quiz"),
            InlineKeyboardButton("💼 Mock Interview", callback_data="btn_interview"),
        ],
        [
            InlineKeyboardButton("🔐 Gen Password", callback_data="btn_genpass"),
            InlineKeyboardButton("🛡️ OWASP Top 10", callback_data="btn_owasp"),
        ],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    if update.message:
        await update.message.reply_text(welcome_text, parse_mode="Markdown", reply_markup=reply_markup)
    elif update.callback_query:
        await update.callback_query.message.reply_text(welcome_text, parse_mode="Markdown", reply_markup=reply_markup)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await start_command(update, context)

# --- Threat Intel & Zero-Days ---
async def news_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    source = "thn"
    if context.args and "bleep" in context.args[0].lower():
        source = "bleeping"
    status_msg = await update.message.reply_text("🔄 Fetching latest security news...")
    news_text = get_latest_news(source=source)
    await status_msg.edit_text(news_text, parse_mode="Markdown", disable_web_page_preview=True)

async def cisa_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    status_msg = await update.message.reply_text("🚨 Fetching CISA Known Exploited Vulnerabilities...")
    result = get_cisa_zero_days()
    await status_msg.edit_text(result, parse_mode="Markdown", disable_web_page_preview=True)

async def cve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/cve <CVE-ID>`\nExample: `/cve CVE-2024-3094`", parse_mode="Markdown")
        return
    cve_id = context.args[0]
    status_msg = await update.message.reply_text(f"🔍 Searching CVE database for `{cve_id}`...", parse_mode="Markdown")
    result = lookup_cve(cve_id)
    await status_msg.edit_text(result, parse_mode="Markdown", disable_web_page_preview=True)

async def ioc_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/ioc <hash_ip_or_domain>`\nExample: `/ioc 1.1.1.1` or `/ioc 44d88612fea8a8f36de82e1278abb02f`", parse_mode="Markdown")
        return
    result = analyze_ioc(context.args[0])
    await update.message.reply_text(result, parse_mode="Markdown", disable_web_page_preview=True)

async def pwned_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/pwned <email>`\nExample: `/pwned test@example.com`", parse_mode="Markdown")
        return
    status_msg = await update.message.reply_text("🔎 Checking breach database...", parse_mode="Markdown")
    result = check_breach(context.args[0])
    await status_msg.edit_text(result, parse_mode="Markdown")

# --- Phishing & Email Defense ---
async def dmarc_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/dmarc <domain>`\nExample: `/dmarc paypal.com`", parse_mode="Markdown")
        return
    status_msg = await update.message.reply_text(f"📧 Auditing SPF/DMARC records for `{context.args[0]}`...", parse_mode="Markdown")
    result = check_email_security(context.args[0])
    await status_msg.edit_text(result, parse_mode="Markdown")

async def expand_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/expand <short_url>`\nExample: `/expand https://bit.ly/3xyz`", parse_mode="Markdown")
        return
    status_msg = await update.message.reply_text("🔗 Tracing HTTP redirects...", parse_mode="Markdown")
    result = expand_short_url(context.args[0])
    await status_msg.edit_text(result, parse_mode="Markdown", disable_web_page_preview=True)

async def epoch_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ts = context.args[0] if context.args else "now"
    result = convert_epoch(ts)
    await update.message.reply_text(result, parse_mode="Markdown")

# --- Career & Interview ---
# In-memory store for active interview answers
INTERVIEW_ANSWERS = {}

async def send_interview_question(chat_target, role="soc", is_callback=False):
    item = get_random_interview(role)
    q_id = str(hash(item["q"]) % 1000000)
    INTERVIEW_ANSWERS[q_id] = item["a"]

    text = f"💼 *Cybersecurity Technical Interview ({role.upper()})*\n━━━━━━━━━━━━━━━━━━\n\n*{item['q']}*"
    keyboard = [[InlineKeyboardButton("👁️ Reveal Answer", callback_data=f"ans_{q_id}")]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    if is_callback:
        await chat_target.message.reply_text(text, parse_mode="Markdown", reply_markup=reply_markup)
    else:
        await chat_target.reply_text(text, parse_mode="Markdown", reply_markup=reply_markup)

async def interview_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    role = context.args[0].lower() if context.args else "soc"
    await send_interview_question(update.message, role=role, is_callback=False)

async def roadmap_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    path = context.args[0].lower() if context.args else "soc"
    result = get_roadmap(path)
    await update.message.reply_text(result, parse_mode="Markdown")

# --- Subscriptions & Briefings ---
async def subscribe_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    result = subscribe_chat(chat_id)
    await update.message.reply_text(result, parse_mode="Markdown")

async def unsubscribe_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    result = unsubscribe_chat(chat_id)
    await update.message.reply_text(result, parse_mode="Markdown")

async def briefing_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    status_msg = await update.message.reply_text("🔄 Generating threat briefing...")
    result = build_daily_briefing()
    await status_msg.edit_text(result, parse_mode="Markdown", disable_web_page_preview=True)

# --- OSINT & Network Recon ---
async def whois_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/whois <domain>`\nExample: `/whois github.com`", parse_mode="Markdown")
        return
    domain = context.args[0]
    status_msg = await update.message.reply_text(f"📋 Looking up WHOIS/RDAP for `{domain}`...", parse_mode="Markdown")
    result = lookup_whois(domain)
    await status_msg.edit_text(result, parse_mode="Markdown")

async def subdomains_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/subdomains <domain>`\nExample: `/subdomains github.com`", parse_mode="Markdown")
        return
    domain = context.args[0]
    status_msg = await update.message.reply_text(f"🔎 Enumerating subdomains for `{domain}`...", parse_mode="Markdown")
    result = find_subdomains(domain)
    await status_msg.edit_text(result, parse_mode="Markdown")

async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/ip <target>`\nExample: `/ip 8.8.8.8`", parse_mode="Markdown")
        return
    target = context.args[0]
    status_msg = await update.message.reply_text(f"🌐 Querying network intelligence for `{target}`...", parse_mode="Markdown")
    result = lookup_ip(target)
    await status_msg.edit_text(result, parse_mode="Markdown", disable_web_page_preview=True)

async def ssl_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/ssl <domain>`\nExample: `/ssl github.com`", parse_mode="Markdown")
        return
    domain = context.args[0]
    status_msg = await update.message.reply_text(f"🔒 Checking SSL certificate for `{domain}`...", parse_mode="Markdown")
    result = check_ssl(domain)
    await status_msg.edit_text(result, parse_mode="Markdown")

async def headers_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/headers <url>`\nExample: `/headers google.com`", parse_mode="Markdown")
        return
    target_url = context.args[0]
    status_msg = await update.message.reply_text(f"🛡️ Auditing security headers for `{target_url}`...", parse_mode="Markdown")
    result = check_headers(target_url)
    await status_msg.edit_text(result, parse_mode="Markdown")

async def dns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/dns <domain>`\nExample: `/dns cloudflare.com`", parse_mode="Markdown")
        return
    domain = context.args[0]
    status_msg = await update.message.reply_text(f"🌐 Querying DNS records for `{domain}`...", parse_mode="Markdown")
    result = query_dns(domain)
    await status_msg.edit_text(result, parse_mode="Markdown")

async def port_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/port <number>`\nExample: `/port 445`", parse_mode="Markdown")
        return
    result = port_info(context.args[0])
    await update.message.reply_text(result, parse_mode="Markdown")

async def cidr_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/cidr <subnet>`\nExample: `/cidr 192.168.1.0/24`", parse_mode="Markdown")
        return
    result = calculate_cidr(context.args[0])
    await update.message.reply_text(result, parse_mode="Markdown")

async def mac_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/mac <address>`\nExample: `/mac 00:1A:2B:3C:4D:5E`", parse_mode="Markdown")
        return
    result = lookup_mac(context.args[0])
    await update.message.reply_text(result, parse_mode="Markdown")

async def useragent_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/useragent <string>`", parse_mode="Markdown")
        return
    result = parse_useragent(" ".join(context.args))
    await update.message.reply_text(result, parse_mode="Markdown")

# --- Crypto & Utilities ---
async def genpass_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    length = 16
    if context.args:
        try: length = int(context.args[0])
        except ValueError: pass
    result = generate_password(length)
    await update.message.reply_text(result, parse_mode="Markdown")

async def checkpass_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/checkpass <password>`\nExample: `/checkpass Tr0ub4dor&3`", parse_mode="Markdown")
        return
    result = check_password_strength(" ".join(context.args))
    await update.message.reply_text(result, parse_mode="Markdown")

async def hash_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/hash <text>`\nExample: `/hash admin123`", parse_mode="Markdown")
        return
    result = compute_hashes(" ".join(context.args))
    await update.message.reply_text(result, parse_mode="Markdown")

async def encode_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text("⚠️ Usage: `/encode <base64|url|hex> <text>`", parse_mode="Markdown")
        return
    result = encode_text(context.args[0], " ".join(context.args[1:]))
    await update.message.reply_text(result, parse_mode="Markdown")

async def decode_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text("⚠️ Usage: `/decode <base64|url|hex> <text>`", parse_mode="Markdown")
        return
    result = decode_text(context.args[0], " ".join(context.args[1:]))
    await update.message.reply_text(result, parse_mode="Markdown")

async def defang_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/defang <url_or_ip>`\nExample: `/defang https://malicious-site.com`", parse_mode="Markdown")
        return
    result = defang_indicator(context.args[0])
    await update.message.reply_text(result, parse_mode="Markdown")

async def refang_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/refang <indicator>`\nExample: `/refang hxxps[://]evil[.]com`", parse_mode="Markdown")
        return
    result = refang_indicator(context.args[0])
    await update.message.reply_text(result, parse_mode="Markdown")

async def rot13_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/rot13 <text>`\nExample: `/rot13 cvat`", parse_mode="Markdown")
        return
    result = rot13(" ".join(context.args))
    await update.message.reply_text(result, parse_mode="Markdown")

async def caesar_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text("⚠️ Usage: `/caesar <shift> <text>`\nExample: `/caesar 3 Attack at dawn`", parse_mode="Markdown")
        return
    try: shift = int(context.args[0])
    except ValueError:
        await update.message.reply_text("⚠️ Shift must be a number! Example: `/caesar 3 hello`", parse_mode="Markdown")
        return
    result = caesar_cipher(" ".join(context.args[1:]), shift)
    await update.message.reply_text(result, parse_mode="Markdown")

async def cheat_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    result = get_cheatsheet(context.args[0] if context.args else "")
    await update.message.reply_text(result, parse_mode="Markdown")

async def ask_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: `/ask <Question>`", parse_mode="Markdown")
        return
    status_msg = await update.message.reply_text("🤖 Consulting CyberSec AI...")
    answer = ask_cyber_ai(" ".join(context.args))
    if len(answer) > 4000:
        answer = answer[:3990] + "\n\n*(Message truncated)*"
    try: await status_msg.edit_text(answer, parse_mode="Markdown")
    except Exception: await status_msg.edit_text(answer)

# --- Quiz ---
async def send_quiz(chat_target, is_callback=False):
    q_data = get_random_quiz()
    question = q_data["q"]
    options = q_data["options"]
    correct_idx = q_data["correct"]

    text = f"🎯 *CyberSecurity Quiz*\n━━━━━━━━━━━━━━━━━━\n\n*{question}*"
    buttons = []
    for idx, opt in enumerate(options):
        is_correct = 1 if idx == correct_idx else 0
        buttons.append([InlineKeyboardButton(f"{chr(65+idx)}. {opt}", callback_data=f"qz_{is_correct}_{correct_idx}")])

    reply_markup = InlineKeyboardMarkup(buttons)
    if is_callback:
        await chat_target.message.reply_text(text, parse_mode="Markdown", reply_markup=reply_markup)
    else:
        await chat_target.reply_text(text, parse_mode="Markdown", reply_markup=reply_markup)

async def quiz_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await send_quiz(update.message, is_callback=False)

# --- Callbacks ---
async def button_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "btn_news":
        news_text = get_latest_news(source="thn")
        await query.message.reply_text(news_text, parse_mode="Markdown", disable_web_page_preview=True)
    elif data == "btn_cisa":
        cisa_text = get_cisa_zero_days()
        await query.message.reply_text(cisa_text, parse_mode="Markdown", disable_web_page_preview=True)
    elif data == "btn_genpass":
        res = generate_password(16)
        await query.message.reply_text(res, parse_mode="Markdown")
    elif data == "btn_owasp":
        res = get_cheatsheet("owasp")
        await query.message.reply_text(res, parse_mode="Markdown")
    elif data == "btn_quiz":
        await send_quiz(query, is_callback=True)
    elif data == "btn_interview":
        await send_interview_question(query, role="soc", is_callback=True)
    elif data.startswith("ans_"):
        q_id = data.split("_")[1]
        model_answer = INTERVIEW_ANSWERS.get(q_id, "Answer record expired.")
        await query.message.reply_text(model_answer, parse_mode="Markdown")
    elif data.startswith("qz_"):
        parts = data.split("_")
        is_correct = parts[1] == "1"
        correct_idx = int(parts[2])
        letter = chr(65 + correct_idx)
        if is_correct:
            result_text = f"🎉 *Correct!* You nailed it! Option *{letter}* is the right answer."
        else:
            result_text = f"❌ *Incorrect.* The correct answer was *{letter}*."
        keyboard = [[InlineKeyboardButton("Next Question ➡️", callback_data="btn_quiz")]]
        await query.message.reply_text(result_text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
