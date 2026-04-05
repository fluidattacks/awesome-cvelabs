#!/usr/bin/env python3
"""Integrity Labs scraper — Playwright edition.
Source: Sitemap → /advisories/ pages → date, CVE IDs, researchers, vendors.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Integrity Labs"
URL = "https://labs.integrity.pt"
SITEMAP_URL = "https://labs.integrity.pt/sitemap.xml"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


async def _get_advisory_urls(page) -> list[str]:
    try:
        await page.goto(SITEMAP_URL, wait_until="networkidle", timeout=30000)
    except Exception:
        return []

    content = await page.content()
    locs = re.findall(r"<loc>([^<]+/advisories/[^<]+)</loc>", content)
    seen: set[str] = set()
    urls = []
    for loc in locs:
        if loc.rstrip("/").endswith("/advisories"):
            continue
        if loc not in seen:
            seen.add(loc)
            urls.append(loc)
    return urls


async def _parse_page(page, url: str) -> Advisory | None:
    try:
        resp = await page.goto(url, wait_until="networkidle", timeout=30000)
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
    disc_m = re.search(r"(?:Researcher|Discovered|Author|Found)[:\s]+([^\n,\.]{3,50})", text, re.IGNORECASE)
    if disc_m:
        name = disc_m.group(1).strip()
        if name and len(name) < 60:
            researchers = [name]

    # Vendors
    vendors = []
    vendor_m = re.search(r"(?:Vendor|Affected Vendor)[:\s]+([^\n,\.]{2,40})", text, re.IGNORECASE)
    if vendor_m:
        v = vendor_m.group(1).strip()
        if v:
            vendors = [v]

    return Advisory(url=url, date=date_str, cve_ids=cves, researchers=researchers, vendors=vendors)


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
