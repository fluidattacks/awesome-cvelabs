#!/usr/bin/env python3
"""NCC Group scraper — Playwright edition.
Source: Sitemap → /technical-advisory/ pages → date, CVE IDs, researchers, vendors.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "NCC Group"
URL = "https://www.nccgroup.com"
SITEMAP_URL = "https://www.nccgroup.com/sitemap.xml"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
DATE_RE = re.compile(
    r"\b(\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+\d{4}|\d{4}-\d{2}-\d{2})\b",
    re.IGNORECASE,
)
TA_RE = re.compile(r"Technical Advisory[:\s]+(.+?)(?:\s*[-–|]|$)", re.IGNORECASE)


async def _get_advisory_urls(api) -> list[str]:
    """Fetch sitemap via raw HTTP — avoids browser XML truncation (sitemap is 650KB+)."""
    try:
        resp = await api.get(SITEMAP_URL)
        content = await resp.text()
    except Exception:
        return []
    locs = re.findall(
        r"<loc>(https://www\.nccgroup\.com/[^<]+technical-advisory[^<]+)</loc>",
        content,
    )
    return list(dict.fromkeys(locs))


async def _parse_page(page, url: str) -> Advisory | None:
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        if resp and resp.status != 200:
            return None
    except Exception:
        return None

    html = await page.content()
    soup = BeautifulSoup(html, "html.parser")
    lines = [l.strip() for l in soup.get_text("\n").splitlines() if l.strip()]
    full_text = " ".join(lines)

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(full_text)))

    date_str = None
    m = DATE_RE.search(full_text)
    if m:
        s = m.group(1)
        for fmt in ("%d %B %Y", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s, fmt)
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass

    vendor = []
    h1 = soup.find("h1")
    if h1:
        title = h1.get_text(strip=True)
        m2 = TA_RE.match(title)
        if m2:
            raw = m2.group(1).strip()
            product = re.split(r"\s+[-–]\s+", raw)[0].strip()
            if product and len(product) < 100:
                vendor = [product]

    researcher = []
    meta_author = soup.find("meta", {"name": "author"})
    if meta_author and meta_author.get("content"):
        name = meta_author["content"].strip()
        if name and len(name) < 80:
            researcher = [name]
    if not researcher:
        for line in lines:
            m3 = re.match(r"^(?:Written by|Author)[:\s]+(.+)", line, re.IGNORECASE)
            if m3:
                name = m3.group(1).strip()
                if name and len(name) < 80:
                    researcher = [name]
                break

    return Advisory(url=url, date=date_str, cve_ids=cves,
                    researchers=researcher, vendors=vendor)


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
