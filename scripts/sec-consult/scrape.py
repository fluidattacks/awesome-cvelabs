#!/usr/bin/env python3
"""SEC Consult scraper — Playwright edition.
Source: Sitemap index → advisory sub-sitemap → advisory pages → date, CVE IDs.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from html import unescape
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "SEC Consult"
URL = "https://sec-consult.com"
SITEMAP_URL = "https://sec-consult.com/sitemap.xml"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
ADVISORY_KEYWORDS = ["vulnerability-lab", "advisories", "advisory", "security-notice"]


async def _get_advisory_urls(api) -> list[str]:
    seen: set[str] = set()
    urls = []

    try:
        resp = await api.get(SITEMAP_URL)
        if resp.status != 200:
            return []
        content = await resp.text()
    except Exception:
        return []

    # Sub-sitemaps URLs may contain &amp; — unescape before fetching
    sub_sitemaps = [unescape(l) for l in re.findall(r"<loc>([^<]+)</loc>", content)
                    if "sitemap" in l.lower()]

    for sm in sub_sitemaps:
        try:
            r2 = await api.get(sm)
            if r2.status != 200:
                continue
            sub = await r2.text()
            for loc in re.findall(r"<loc>([^<]+)</loc>", sub):
                loc = unescape(loc)
                if any(kw in loc.lower() for kw in ADVISORY_KEYWORDS) and loc not in seen:
                    seen.add(loc)
                    urls.append(loc)
        except Exception:
            pass

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

    return Advisory(url=url, date=date_str, cve_ids=cves)


async def scrape() -> list[Advisory]:
    advisories = []
    async with async_playwright() as p:
        api = await p.request.new_context()
        browser = await p.chromium.launch()
        page = await browser.new_page()
        adv_urls = await _get_advisory_urls(api)
        for url in adv_urls:
            adv = await _parse_page(page, url)
            if adv:
                advisories.append(adv)
        await browser.close()
        await api.dispose()
    return advisories


if __name__ == "__main__":
    advisories = [a for a in asyncio.run(scrape()) if a.cve_ids]
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
