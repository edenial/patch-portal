#!/usr/bin/env python3
import re, json
from pathlib import Path
from datetime import datetime, timedelta, timezone
import feedparser, yaml
from dateutil import parser as dtp
from config import MAX_AGE_DAYS, PRODUCT_KEYWORDS

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "site" / "advisories.json"
SOURCES = Path(__file__).parent / "sources.yaml"

def norm(s): 
    import re
    return re.sub(r"\s+", " ", (s or "")).strip()

def parse_dt(x):
    if not x: return None
    try:
        d = dtp.parse(x)
        if not d.tzinfo: d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc)
    except Exception:
        return None

def within_age(dt, days):
    if not dt: return True
    return (datetime.now(timezone.utc) - dt) <= timedelta(days=days)

def accept(title, summary):
    if not PRODUCT_KEYWORDS: return True
    hay = f"{title} {summary}".lower()
    return any(k.lower() in hay for k in PRODUCT_KEYWORDS)

def collect_rss(name, url):
    feed = feedparser.parse(url)
    out = []
    vend = feed.feed.get("title", name)
    for e in feed.entries:
        published = parse_dt(getattr(e, "published", None) or getattr(e, "updated", None))
        title = norm(getattr(e, "title", ""))
        summary = norm(getattr(e, "summary", "") or getattr(e, "description",""))
        link = getattr(e, "link", "")
        if not accept(title, summary): 
            continue
        if not within_age(published, MAX_AGE_DAYS):
            continue
        out.append({
            "source": url,
            "vendor": vend,
            "title": title,
            "summary": summary,
            "url": link,
            "published": published.isoformat() if published else None,
            "severity": None,
            "product": None,
            "cve_ids": re.findall(r"CVE-\d{4}-\d{4,7}", f"{title} {summary}")
        })
    return out

def dedupe(rows):
    seen=set(); out=[]
    for r in sorted(rows, key=lambda x: (x.get("published") or "", x.get("title") or ""), reverse=True):
        key = r.get("url") or r.get("title")
        if key in seen: 
            continue
        seen.add(key); out.append(r)
    return out

def main():
    cfg = yaml.safe_load(open(SOURCES))
    items = []
    for s in cfg.get("rss", []):
        if not s.get("enabled"): 
            continue
        items.extend(collect_rss(s.get("name"), s.get("url")))
    items = dedupe(items)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.utcnow().isoformat()+"Z", "count": len(items), "items": items}, f, indent=2)
    print(f"Wrote {OUT} with {len(items)} items.")

if __name__ == "__main__":
    main()
