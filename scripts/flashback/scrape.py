#!/usr/bin/env python3
"""Flashback scraper — Playwright edition.
Source: Squarespace JSON API /blog?format=json → date, CVE IDs, vendors, researchers.
Vendor and researcher extracted from post title/body.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Flashback"
URL = "https://www.flashback.sh"
BLOG_JSON = URL + "/blog?format=json"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


def _vendor_from_title(title: str) -> list[str]:
    m = re.search(r"([A-Z][A-Za-z0-9\.\-\s]+?)\s+(?:\()?CVE-\d{4}-\d+", title)
    if m:
        product = m.group(1).strip()
        if product and 2 < len(product) < 60:
            return [product]
    return []


async def scrape() -> list[Advisory]:
    async with async_playwright() as p:
        api = await p.request.new_context()
        try:
            resp = await api.get(BLOG_JSON)
            data = await resp.json()
        except Exception as e:
            print(f"  Error fetching blog JSON: {e}")
            await api.dispose()
            return []
        await api.dispose()

    items = sorted(data.get("items", []), key=lambda x: x.get("publishOn", 0), reverse=True)
    advisories = []
    seen_cves: set[str] = set()

    for item in items:
        full_url = item.get("fullUrl", "")
        if not full_url or "/blog/" not in full_url:
            continue
        if full_url.startswith("/"):
            full_url = URL + full_url

        date_str = None
        publish_on = item.get("publishOn")
        if publish_on:
            try:
                dt = datetime.fromtimestamp(publish_on / 1000, tz=timezone.utc)
                date_str = dt.strftime("%y/%m/%d")
            except (ValueError, OSError):
                pass

        body_html = item.get("body", "") or ""
        body_text = BeautifulSoup(body_html, "html.parser").get_text(" ")
        title = item.get("title", "")
        cves = [c.upper() for c in CVE_RE.findall(title + " " + body_text)]
        new_cves = [c for c in dict.fromkeys(cves) if c not in seen_cves]
        for c in new_cves:
            seen_cves.add(c)

        vendor = _vendor_from_title(title)

        researcher = []
        author = item.get("author", {})
        if isinstance(author, dict):
            name = author.get("displayName", "").strip()
            if name and len(name) < 80:
                researcher = [name]
        if not researcher:
            m = re.search(r"\bby\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})", body_text)
            if m:
                name = m.group(1).strip()
                if name and len(name) < 60:
                    researcher = [name]

        advisories.append(Advisory(url=full_url, date=date_str, cve_ids=new_cves,
                                   researchers=researcher, vendors=vendor))

    return advisories


if __name__ == "__main__":
    advisories = [a for a in asyncio.run(scrape()) if a.cve_ids]
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
