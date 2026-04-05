#!/usr/bin/env python3
"""SentinelOne scraper — Playwright edition.
Source: /labs/our-cves/ no longer exists; use RSS feed at /labs/feed/ (paginated).
Fetches all blog post URLs, visits each, keeps only those with CVE IDs.
"""
import asyncio, html as html_mod, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "SentinelOne"
URL = "https://www.sentinelone.com/labs/our-cves/"
RSS_BASE = "https://www.sentinelone.com/labs/feed/"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
MAX_FEED_PAGES = 50  # safety cap (~500 posts)


async def _get_advisory_urls(page) -> list[str]:
    seen: set[str] = set()
    urls = []

    for feed_page in range(1, MAX_FEED_PAGES + 1):
        feed_url = RSS_BASE if feed_page == 1 else f"{RSS_BASE}?paged={feed_page}"
        try:
            await page.goto(feed_url, wait_until="domcontentloaded", timeout=30000)
        except Exception:
            break

        # Playwright HTML-escapes XML inside <pre> — unescape first
        content = html_mod.unescape(await page.content())
        # Extract post URLs and their descriptions from RSS items
        items = re.findall(r"<item>(.*?)</item>", content, re.DOTALL)
        if not items:
            break

        new_found = False
        for item in items:
            link_m = re.search(r"<link>([^<]+)</link>", item)
            if not link_m:
                continue
            post_url = link_m.group(1).strip()
            if post_url in seen:
                continue
            # Pre-filter: only visit pages that mention CVE in the RSS description/title
            desc = re.search(r"<description>(.*?)</description>", item, re.DOTALL)
            title = re.search(r"<title>(.*?)</title>", item, re.DOTALL)
            combined = (desc.group(1) if desc else "") + (title.group(1) if title else "")
            if CVE_RE.search(combined):
                seen.add(post_url)
                urls.append(post_url)
                new_found = True

        if len(items) < 10:  # last page has fewer items
            break

    return urls


async def _parse_page(page, url: str) -> Advisory | None:
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        if resp and resp.status != 200:
            return None
    except Exception:
        return None

    html = await page.content()
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ")

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(text)))

    # Date
    date_str = None
    time_tag = soup.find("time")
    if time_tag:
        dt_attr = time_tag.get("datetime", "") or time_tag.get_text(strip=True)
        try:
            dt = datetime.fromisoformat(dt_attr[:10])
            date_str = dt.strftime("%y/%m/%d")
        except ValueError:
            pass
    if not date_str:
        m = re.search(r"(\d{4}-\d{2}-\d{2})", text)
        if m:
            try:
                dt = datetime.strptime(m.group(1), "%Y-%m-%d")
                date_str = dt.strftime("%y/%m/%d")
            except ValueError:
                pass

    # Researchers
    researchers = []
    disc_m = re.search(r"(?:Author|Researcher|By)[:\s]+([^\n,\.]{3,50})", text, re.IGNORECASE)
    if disc_m:
        name = disc_m.group(1).strip()
        if name and len(name) < 60:
            researchers = [name]

    return Advisory(url=url, date=date_str, cve_ids=cves, researchers=researchers)


async def scrape() -> list[Advisory]:
    advisories = []
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        adv_urls = await _get_advisory_urls(page)
        for url in adv_urls:
            adv = await _parse_page(page, url)
            if adv:
                advisories.append(adv)
        await browser.close()
    return advisories


if __name__ == "__main__":
    advisories = [a for a in asyncio.run(scrape()) if a.cve_ids]
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
