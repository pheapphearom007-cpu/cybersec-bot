import sys
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging
import datetime
from telegram import BotCommand
from telegram.error import Conflict
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

from config import TELEGRAM_BOT_TOKEN
from handlers.command_handlers import (
    start_command,
    help_command,
    ask_command,
    news_command,
    cisa_command,
    cve_command,
    ioc_command,
    pwned_command,
    dmarc_command,
    expand_command,
    whois_command,
    subdomains_command,
    ip_command,
    ssl_command,
    headers_command,
    dns_command,
    port_command,
    cidr_command,
    mac_command,
    useragent_command,
    epoch_command,
    genpass_command,
    checkpass_command,
    hash_command,
    defang_command,
    refang_command,
    encode_command,
    decode_command,
    rot13_command,
    caesar_command,
    cheat_command,
    quiz_command,
    interview_command,
    roadmap_command,
    subscribe_command,
    unsubscribe_command,
    briefing_command,
    button_callback_handler,
)
from handlers.message_handlers import handle_direct_message, handle_file_attachment

# Set up logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("CyberSecBot")

class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Bot is alive and running!")

    def log_message(self, format, *args):
        # Suppress noisy keep-alive ping logs in console
        pass

def start_health_server():
    port = int(os.environ.get("PORT", 8080))
    server = HTTPServer(("0.0.0.0", port), HealthCheckHandler)
    server.serve_forever()

async def post_init(application: Application):
    """Register commands with Telegram so they appear in the / autocomplete menu."""
    commands = [
        BotCommand("start", "Main menu & quick actions"),
        BotCommand("help", "List all features & commands"),
        BotCommand("news", "Latest cybersecurity threat news"),
        BotCommand("cisa", "Actively exploited zero-days (KEV)"),
        BotCommand("cve", "Lookup CVE vulnerability & CVSS"),
        BotCommand("ioc", "Universal IoC reputation scanner"),
        BotCommand("pwned", "Check leaked data & breaches"),
        BotCommand("dmarc", "Email spoofing & SPF/DMARC audit"),
        BotCommand("expand", "Unshorten redirect links (bit.ly)"),
        BotCommand("whois", "Lookup domain WHOIS/RDAP records"),
        BotCommand("subdomains", "Find domain subdomains"),
        BotCommand("ip", "Inspect IP threat & network info"),
        BotCommand("ssl", "Check SSL/TLS certificate expiry"),
        BotCommand("headers", "Audit HTTP security headers"),
        BotCommand("dns", "Query DNS records (DoH)"),
        BotCommand("port", "Port & exploit reference"),
        BotCommand("cidr", "Subnet & CIDR calculator"),
        BotCommand("mac", "Lookup hardware MAC vendor"),
        BotCommand("useragent", "Analyze browser User-Agent"),
        BotCommand("epoch", "Convert Unix epoch timestamp"),
        BotCommand("genpass", "Generate secure random password"),
        BotCommand("checkpass", "Test password strength & entropy"),
        BotCommand("hash", "Generate MD5, SHA-1, SHA-256"),
        BotCommand("defang", "Sanitize malicious URL/IP links"),
        BotCommand("refang", "Restore defanged links"),
        BotCommand("encode", "Encode to Base64, URL, Hex"),
        BotCommand("decode", "Decode from Base64, URL, Hex"),
        BotCommand("rot13", "ROT13 cipher encoder/decoder"),
        BotCommand("caesar", "Caesar cipher with custom shift"),
        BotCommand("quiz", "Interactive cybersecurity trivia"),
        BotCommand("interview", "Technical mock interview"),
        BotCommand("roadmap", "Cyber career paths (soc/pentest)"),
        BotCommand("subscribe", "Daily automated threat briefing"),
        BotCommand("unsubscribe", "Stop daily threat briefings"),
        BotCommand("briefing", "Trigger threat briefing now"),
        BotCommand("cheat", "Cheatsheets (nmap, linux, owasp)"),
        BotCommand("ask", "Ask AI any cybersecurity question"),
    ]
    try:
        await application.bot.set_my_commands(commands)
        logger.info("Successfully registered Telegram bot command menu.")
    except Exception as e:
        logger.warning(f"Could not register commands menu: {e}")

async def daily_briefing_job(context: ContextTypes.DEFAULT_TYPE):
    """JobQueue scheduled callback for daily threat briefing."""
    from services.subscription_service import get_subscribers, build_daily_briefing
    subscribers = get_subscribers()
    if not subscribers:
        return

    logger.info(f"Delivering daily threat briefing to {len(subscribers)} subscribers...")
    briefing_text = build_daily_briefing()
    for chat_id in subscribers:
        try:
            await context.bot.send_message(
                chat_id=chat_id,
                text=briefing_text,
                parse_mode="Markdown",
                disable_web_page_preview=True,
            )
        except Exception as e:
            logger.warning(f"Failed to send briefing to {chat_id}: {e}")

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Log errors caused by updates and handle conflicts cleanly."""
    if isinstance(context.error, Conflict):
        logger.warning(
            "Conflict detected: Another bot instance is polling getUpdates with the same token. "
            "Ensure only ONE instance is running (e.g. stop local systemd service or duplicate cloud instance)."
        )
    else:
        logger.error("Exception while handling an update:", exc_info=context.error)

def main():
    if not TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN == "your_telegram_bot_token_here":
        logger.error(
            "\n"
            "==========================================================\n"
            "❌ ERROR: TELEGRAM_BOT_TOKEN is not set!\n"
            "==========================================================\n"
        )
        sys.exit(1)

    logger.info("Starting CyberSec Bot...")
    app = (
        Application.builder()
        .token(TELEGRAM_BOT_TOKEN)
        .post_init(post_init)
        .build()
    )

    # Core & Educational
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("ask", ask_command))
    app.add_handler(CommandHandler("quiz", quiz_command))
    app.add_handler(CommandHandler("interview", interview_command))
    app.add_handler(CommandHandler("roadmap", roadmap_command))

    # Threat Intelligence & Zero-Days
    app.add_handler(CommandHandler("news", news_command))
    app.add_handler(CommandHandler("cisa", cisa_command))
    app.add_handler(CommandHandler("cve", cve_command))
    app.add_handler(CommandHandler("ioc", ioc_command))
    app.add_handler(CommandHandler("pwned", pwned_command))

    # Email & Phishing Defense
    app.add_handler(CommandHandler("dmarc", dmarc_command))
    app.add_handler(CommandHandler("expand", expand_command))

    # Network Recon & OSINT
    app.add_handler(CommandHandler("whois", whois_command))
    app.add_handler(CommandHandler("subdomains", subdomains_command))
    app.add_handler(CommandHandler("ip", ip_command))
    app.add_handler(CommandHandler("ssl", ssl_command))
    app.add_handler(CommandHandler("headers", headers_command))
    app.add_handler(CommandHandler("dns", dns_command))
    app.add_handler(CommandHandler("port", port_command))
    app.add_handler(CommandHandler("cidr", cidr_command))
    app.add_handler(CommandHandler("mac", mac_command))
    app.add_handler(CommandHandler("useragent", useragent_command))
    app.add_handler(CommandHandler("epoch", epoch_command))

    # Cryptography & Utilities
    app.add_handler(CommandHandler("genpass", genpass_command))
    app.add_handler(CommandHandler("checkpass", checkpass_command))
    app.add_handler(CommandHandler("hash", hash_command))
    app.add_handler(CommandHandler("defang", defang_command))
    app.add_handler(CommandHandler("refang", refang_command))
    app.add_handler(CommandHandler("encode", encode_command))
    app.add_handler(CommandHandler("decode", decode_command))
    app.add_handler(CommandHandler("rot13", rot13_command))
    app.add_handler(CommandHandler("caesar", caesar_command))

    # Subscriptions & Briefings
    app.add_handler(CommandHandler("subscribe", subscribe_command))
    app.add_handler(CommandHandler("unsubscribe", unsubscribe_command))
    app.add_handler(CommandHandler("briefing", briefing_command))

    # Cheatsheets
    app.add_handler(CommandHandler("cheat", cheat_command))

    # Interactive buttons & File attachment scanner
    app.add_handler(CallbackQueryHandler(button_callback_handler))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file_attachment))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_direct_message))

    # Register error handler
    app.add_error_handler(error_handler)

    # Schedule Daily Threat Briefing at 09:00 UTC (16:00 Local)
    if app.job_queue:
        app.job_queue.run_daily(
            daily_briefing_job,
            time=datetime.time(hour=9, minute=0, tzinfo=datetime.timezone.utc),
        )
        logger.info("Daily Threat Briefing job scheduled for 09:00 UTC daily.")

    # Start background web server for free 24/7 cloud hosting keep-alive
    threading.Thread(target=start_health_server, daemon=True).start()
    logger.info("Keep-alive health server running on port %s", os.environ.get("PORT", 8080))

    logger.info("Bot is active and polling for updates! Press Ctrl+C to stop.")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
