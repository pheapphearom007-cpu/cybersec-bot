import json
from pathlib import Path
from services.news_service import get_latest_news
from services.threat_service import get_cisa_zero_days

SUBSCRIPTIONS_FILE = Path(__file__).resolve().parent.parent / "subscriptions.json"

def _load_subs() -> set:
    if not SUBSCRIPTIONS_FILE.exists():
        return set()
    try:
        with open(SUBSCRIPTIONS_FILE, "r") as f:
            data = json.load(f)
            return set(data.get("subscribers", []))
    except Exception:
        return set()

def _save_subs(subs: set):
    try:
        with open(SUBSCRIPTIONS_FILE, "w") as f:
            json.dump({"subscribers": list(subs)}, f, indent=2)
    except Exception:
        pass

def subscribe_chat(chat_id: int) -> str:
    subs = _load_subs()
    if chat_id in subs:
        return "ℹ️ You are already subscribed to the Daily Cyber Threat Briefing!"
    subs.add(chat_id)
    _save_subs(subs)
    return (
        "✅ *Subscribed Successfully!*\n\n"
        "You will now receive a daily automated cyber briefing every morning with:\n"
        "• Top breaking cybersecurity news\n"
        "• Newly discovered zero-days from CISA\n\n"
        "💡 _You can unsubscribe anytime with `/unsubscribe`._"
    )

def unsubscribe_chat(chat_id: int) -> str:
    subs = _load_subs()
    if chat_id not in subs:
        return "ℹ️ You are not currently subscribed to daily briefings."
    subs.remove(chat_id)
    _save_subs(subs)
    return "👋 *Unsubscribed.* You will no longer receive daily automated briefings."

def get_subscribers() -> list:
    return list(_load_subs())

def build_daily_briefing() -> str:
    """Build morning cybersecurity intelligence summary."""
    news = get_latest_news(limit=3)
    cisa = get_cisa_zero_days(limit=2)
    return (
        "☀️ *DAILY CYBERSECURITY BRIEFING*\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        f"{news}\n\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        f"{cisa}\n\n"
        "🛡️ _Stay vigilant and keep your systems patched!_"
    )
