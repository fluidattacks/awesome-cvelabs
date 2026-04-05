#!/usr/bin/env python3
"""Portcullis Labs scraper — Playwright edition.
Source: Static HTML advisory index at /advisories/ — CVE IDs in text.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Portcullis Labs"
URL = "https://labs.portcullis.co.uk/advisories/"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
SKIP_PATTERNS = [
    "portcullis.co.uk", "portcullis-security.com", "cisco.com",
    "keyserver.pgp", "google.com", "googleapis.com",
    "twitter.com", "linkedin.com", "facebook.com",
]


async def scrape() -> list[Advisory]:
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        try:
            resp = await page.goto(URL, wait_until="domcontentloaded", timeout=30000)
            if resp and resp.status != 200:
                await browser.close()
                return []
        except Exception:
            await browser.close()
            return []

        html = await page.content()
        soup = BeautifulSoup(html, "html.parser")

        advisories = []
        seen_urls: set[str] = set()
        seen_cves: set[str] = set()

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if any(skip in href for skip in SKIP_PATTERNS):
                continue
            if not href.startswith("http"):
                continue
            if href in seen_urls:
                continue

            parent_text = a_tag.parent.get_text(" ") if a_tag.parent else a_tag.get_text()
            cves = [c.upper() for c in CVE_RE.findall(parent_text)]
            new_cves = [c for c in cves if c not in seen_cves]
            if not new_cves and not cves:
                continue

            seen_urls.add(href)
            for c in new_cves:
                seen_cves.add(c)
            advisories.append(Advisory(url=href, cve_ids=new_cves or cves))

        if not advisories:
            text = soup.get_text(" ")
            all_cves = [c.upper() for c in CVE_RE.findall(text)]
            for cve in dict.fromkeys(all_cves):
                advisories.append(Advisory(url=f"{URL}#{cve}", cve_ids=[cve]))

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
