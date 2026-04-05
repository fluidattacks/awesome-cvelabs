#!/usr/bin/env python3
"""Census Labs scraper — Playwright edition.
Source: Sitemap → /news/ advisory posts → date, CVE IDs, researchers, vendors.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Census Labs"
URL = "https://census-labs.com"
SITEMAP_URL = "https://census-labs.com/sitemap.xml"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
ADVISORY_KEYWORDS = [
    "cve", "vuln", "advisory", "exploit", "overflow", "injection",
    "bypass", "disclosure", "heap", "use-after-free", "arbitrary",
]
SKIP_KEYWORDS = ["/category/", "/tag/", "/page/", "/feed"]


async def _get_advisory_urls(api) -> list[str]:
    try:
        resp = await api.get(SITEMAP_URL)
        content = await resp.text()
    except Exception:
        return []
    locs = re.findall(r"<loc>(https://census-labs\.com/news/[^<]+)</loc>", content)
    seen: set[str] = set()
    urls = []
    for loc in locs:
        if any(s in loc for s in SKIP_KEYWORDS):
            continue
        if any(kw in loc.lower() for kw in ADVISORY_KEYWORDS):
            if loc not in seen:
                seen.add(loc)
                urls.append(loc)
    urls.sort(reverse=True)
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
    if not cves:
        return None

    # Date from URL: /news/YYYY/MM/DD/
    date_str = None
    dm = re.search(r"/news/(\d{4})/(\d{2})/(\d{2})/", url)
    if dm:
        try:
            dt = datetime(int(dm.group(1)), int(dm.group(2)), int(dm.group(3)))
            date_str = dt.strftime("%y/%m/%d")
        except ValueError:
            pass

    # Researchers
    researchers = []
    disc_m = re.search(
        r"(?:Researcher|Discovered|Author|Found|By)[:\s]+([^\n,\.]{3,50})",
        text, re.IGNORECASE,
    )
    if disc_m:
        name = disc_m.group(1).strip()
        if name and len(name) < 60:
            researchers = [name]

    # Vendors
    vendors = []
    vendor_m = re.search(
        r"(?:Vendor|Affected)[:\s]+([^\n,\.]{2,40})", text, re.IGNORECASE,
    )
    if vendor_m:
        v = vendor_m.group(1).strip()
        if v:
            vendors = [v]

    return Advisory(url=url, date=date_str, cve_ids=cves,
                    researchers=researchers, vendors=vendors)


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
