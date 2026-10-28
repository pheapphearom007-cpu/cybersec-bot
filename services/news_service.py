import feedparser
import html
import re

FEEDS = {
    "thn": {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
    },
    "bleeping": {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
    },
}

def clean_html(raw_html: str) -> str:
    """Strip HTML tags and unescape HTML entities."""
    clean_text = re.sub(r"<[^>]+>", "", raw_html)
    return html.unescape(clean_text).strip()

def get_latest_news(source: str = "thn", limit: int = 5) -> str:
    """Fetch latest cybersecurity news from RSS feed."""
    feed_info = FEEDS.get(source.lower(), FEEDS["thn"])
    try:
        parsed = feedparser.parse(feed_info["url"])
        if not parsed.entries:
            return f"⚠️ Could not load headlines from *{feed_info['name']}* right now. Please try again later."

        entries = parsed.entries[:limit]
        lines = [f"📰 *Latest News from {feed_info['name']}*\n"]

        for idx, entry in enumerate(entries, 1):
            title = clean_html(entry.get("title", "No Title"))
            link = entry.get("link", "")
            published = entry.get("published", "")
            
            # Short summary if available
            summary = clean_html(entry.get("summary", ""))
            if len(summary) > 140:
                summary = summary[:137] + "..."

            lines.append(f"*{idx}. [{title}]({link})*")
            if summary:
                lines.append(f"_{summary}_")
            lines.append("")

        lines.append("💡 *Tip:* Use `/news thn` or `/news bleeping` to switch sources.")
        return "\n".join(lines)
    except Exception as e:
        return f"⚠️ Error fetching news: {str(e)}"
