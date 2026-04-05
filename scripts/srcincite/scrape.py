#!/usr/bin/env python3
"""Source Incite scraper — Playwright edition.
Source: /advisories/ listing → each src-XXXX advisory page → date, CVE IDs, researchers, vendors.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Source Incite"
URL = "https://srcincite.io"
INDEX_URL = URL + "/advisories/"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
RELEASE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})\s*[–-]\s*Release of advisory", re.IGNORECASE)


async def _get_advisory_urls(page) -> list[str]:
    try:
        resp = await page.goto(INDEX_URL, wait_until="domcontentloaded", timeout=30000)
        if resp and resp.status != 200:
            return []
    except Exception:
        return []

    html = await page.content()
    soup = BeautifulSoup(html, "html.parser")
    seen: set[str] = set()
    urls = []
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if re.match(r"^src-\d{4}-\d+$", href, re.IGNORECASE):
            full_url = INDEX_URL + href
        elif re.match(r"^/advisories/src-\d{4}-\d+/?$", href, re.IGNORECASE):
            full_url = URL + href.rstrip("/")
        else:
            continue
        if full_url not in seen:
            seen.add(full_url)
            urls.append(full_url)
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
    lines = [l.strip() for l in soup.get_text("\n").splitlines() if l.strip()]
    full_text = "\n".join(lines)

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(full_text)))

    date_str = None
    m = RELEASE_RE.search(full_text)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%Y-%m-%d")
            date_str = dt.strftime("%y/%m/%d")
        except ValueError:
            pass

    vendor = []
    for i, line in enumerate(lines):
        if line in ("Affected Vendors:", "Affected Vendor:") and i + 1 < len(lines):
            v = lines[i + 1].strip()
            if v and v not in ("Affected Products:", "Vulnerability Details:") and len(v) < 80:
                vendor = [v]
            break

    researcher = []
    for i, line in enumerate(lines):
        if line == "Credit:" and i + 1 < len(lines):
            m2 = re.search(r"discovered by\s+(.+?)(?:\s+of\s+|\s*$)", lines[i + 1], re.IGNORECASE)
            if m2:
                name = m2.group(1).strip()
                if name and len(name) < 80:
                    researcher = [name]
            break

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
