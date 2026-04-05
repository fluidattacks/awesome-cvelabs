#!/usr/bin/env python3
"""Bishop Fox scraper — Playwright edition.
Source: RSS feed at /feeds/advisories.rss → each advisory page → date, CVE IDs, researchers.
Advisory URLs live at /blog/<slug> (not /blog/advisories/<slug>).
"""
import asyncio, html, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Bishop Fox"
URL = "https://bishopfox.com"
RSS_URL = URL + "/feeds/advisories.rss"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


async def _get_advisory_urls(page) -> list[str]:
    try:
        await page.goto(RSS_URL, wait_until="domcontentloaded", timeout=60000)
    except Exception:
        return []

    # Playwright wraps XML in <pre> with HTML-escaped content — unescape first
    raw = await page.content()
    content = html.unescape(raw)
    # RSS <link> tags: skip channel link (first match is the site root)
    links = re.findall(r"<link>(https://bishopfox\.com/blog/[^<]+)</link>", content)
    return list(dict.fromkeys(links))


async def _parse_page(page, url: str) -> Advisory | None:
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=60000)
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
    disc_m = re.search(r"(?:Author|Researcher|Discovered by)[:\s]+([^\n,\.]{3,50})", text, re.IGNORECASE)
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
