#!/usr/bin/env python3
"""IOActive scraper — Playwright edition.
Source: sitemap_index.xml → post-sitemap → /resources/disclosures/ pages.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "IOActive"
URL = "https://www.ioactive.com"
SITEMAP_INDEX = "https://www.ioactive.com/sitemap_index.xml"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
ADV_KEYWORDS = ["advisory", "advisori", "disclos", "vulnerab", "cve-", "exploit"]
SKIP_KEYWORDS = [
    "disclosure-policy", "responsible-disclosure", "laws-of-disclosure",
    "retrospective", "malware-doesnt", "adventures-in", "good-and-the-ugly",
]


async def _get_advisory_urls(api) -> list[str]:
    """Fetch sitemaps via raw HTTP (bypasses any browser XML rendering issues)."""
    try:
        resp = await api.get(SITEMAP_INDEX)
        content = await resp.text()
    except Exception:
        return []
    sitemaps = re.findall(r"<loc>([^<]+)</loc>", content)
    post_sitemap = next((s for s in sitemaps if "post-sitemap" in s), None)
    if not post_sitemap:
        return []

    try:
        resp2 = await api.get(post_sitemap)
        content2 = await resp2.text()
    except Exception:
        return []
    locs = re.findall(r"<loc>([^<]+)</loc>", content2)
    seen: set[str] = set()
    urls = []
    for loc in locs:
        loc_lower = loc.lower()
        if (any(k in loc_lower for k in ADV_KEYWORDS) and
                not any(s in loc_lower for s in SKIP_KEYWORDS) and
                loc not in seen):
            seen.add(loc)
            urls.append(loc)
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

    researchers = []
    disc_m = re.search(r"(?:Researcher|Discovered|Author|By)[:\s]+([^\n,\.]{3,60})", text, re.IGNORECASE)
    if disc_m:
        name = disc_m.group(1).strip()
        if name and len(name) < 70:
            researchers = [name]

    vendors = []
    vendor_m = re.search(r"(?:Vendor|Affected Vendor|Company)[:\s]+([^\n,\.]{2,40})", text, re.IGNORECASE)
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
