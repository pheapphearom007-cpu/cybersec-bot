import hashlib
from telegram import Update
from telegram.ext import ContextTypes
from services.ai_service import ask_cyber_ai

async def handle_direct_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle plain text messages by forwarding to CyberSec AI."""
    if not update.message or not update.message.text:
        return

    text = update.message.text.strip()
    status_msg = await update.message.reply_text("🤔 Thinking...")
    answer = ask_cyber_ai(text)
    
    if len(answer) > 4000:
        answer = answer[:3990] + "\n\n*(Message truncated)*"
        
    try:
        await status_msg.edit_text(answer, parse_mode="Markdown")
    except Exception:
        await status_msg.edit_text(answer)

async def handle_file_attachment(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Inspect and compute cryptographic hashes for uploaded documents/files."""
    if not update.message or not update.message.document:
        return

    doc = update.message.document
    file_name = doc.file_name or "Unknown_file"
    file_size_kb = (doc.file_size or 0) / 1024.0
    mime_type = doc.mime_type or "application/octet-stream"

    # Only download files under 20MB for safety and Telegram bot limits
    if doc.file_size and doc.file_size > 20 * 1024 * 1024:
        await update.message.reply_text("⚠️ File exceeds 20MB analysis limit.")
        return

    status_msg = await update.message.reply_text(f"🔬 Analyzing `{file_name}`...")

    try:
        telegram_file = await context.bot.get_file(doc.file_id)
        file_bytes = await telegram_file.download_as_bytearray()

        md5 = hashlib.md5(file_bytes).hexdigest()
        sha1 = hashlib.sha1(file_bytes).hexdigest()
        sha256 = hashlib.sha256(file_bytes).hexdigest()

        reply = (
            f"📁 *File Security Analysis*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"• *File Name:* `{file_name}`\n"
            f"• *Size:* `{file_size_kb:.2f} KB`\n"
            f"• *MIME Type:* `{mime_type}`\n\n"
            f"*Cryptographic Hashes:*\n"
            f"• *MD5:*\n`{md5}`\n"
            f"• *SHA-1:*\n`{sha1}`\n"
            f"• *SHA-256:*\n`{sha256}`\n\n"
            f"🔍 [Check on VirusTotal](https://www.virustotal.com/gui/file/{sha256})\n"
            f"🔍 [MalwareBazaar Database](https://bazaar.abuse.ch/sample/{sha256}/)"
        )
        await status_msg.edit_text(reply, parse_mode="Markdown", disable_web_page_preview=True)

    except Exception as e:
        await status_msg.edit_text(f"⚠️ Error analyzing file: {str(e)}")
