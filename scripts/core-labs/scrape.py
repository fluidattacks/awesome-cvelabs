#!/usr/bin/env python3
"""Core Security Core Labs scraper — Playwright edition.
Source: https://www.coresecurity.com/core-labs/advisories
Previously returned 403 with requests. Playwright renders JS and bypasses basic blocks.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Core Security Core Labs"
URL = "https://www.coresecurity.com"
INDEX_URL = URL + "/core-labs/advisories"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
DATE_RE = re.compile(
    r"\b((?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+\d{1,2},?\s+\d{4}|\d{4}-\d{2}-\d{2})\b",
    re.IGNORECASE,
)


async def _get_advisory_urls(page) -> list[str]:
    try:
        resp = await page.goto(INDEX_URL, wait_until="networkidle", timeout=30000)
        if resp and resp.status == 403:
            print("  NOTE: Core Security still returns 403 — advisory page is blocked")
            return []
    except Exception as e:
        print(f"  NOTE: failed to load index: {e}")
        return []

    html = await page.content()
    soup = BeautifulSoup(html, "html.parser")
    seen: set[str] = set()
    urls = []
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if "/core-labs/advisories/" in href and href != "/core-labs/advisories/":
            full_url = URL + href if href.startswith("/") else href
            if full_url not in seen:
                seen.add(full_url)
                urls.append(full_url)
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
    lines = [l.strip() for l in soup.get_text("\n").splitlines() if l.strip()]
    full_text = " ".join(lines)

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(full_text)))
    if not cves:
        return None

    # Date
    date_str = None
    m = DATE_RE.search(full_text[:3000])
    if m:
        s = m.group(1).replace(",", "")
        for fmt in ("%B %d %Y", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s, fmt)
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass

    # Researcher
    researcher = []
    disc_m = re.search(
        r"(?:Researcher|Discovered by|Author|Credits?)[:\s]+([^\n\.]{3,60})",
        full_text, re.IGNORECASE,
    )
    if disc_m:
        name = disc_m.group(1).strip()
        if name and len(name) < 80:
            researcher = [name]

    # Vendor from h1 or title
    vendor = []
    h1 = soup.find("h1")
    if h1:
        title_text = h1.get_text(strip=True)
        vm = re.search(r"(?:in|for)\s+([A-Za-z0-9][A-Za-z0-9\s\.\-]+?)(?:\s+CVE|\s*$)", title_text, re.IGNORECASE)
        if vm:
            v = vm.group(1).strip()
            if v and len(v) < 60:
                vendor = [v]

    return Advisory(url=url, date=date_str, cve_ids=cves,
                    researchers=researcher, vendors=vendor)


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
