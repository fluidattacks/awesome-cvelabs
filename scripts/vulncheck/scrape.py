#!/usr/bin/env python3
"""VulnCheck scraper — Playwright edition.
Source: Nuxt.js SPA at /advisories — JS rendering required for full CVE list.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "VulnCheck"
URL = "https://vulncheck.com/advisories"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


async def scrape() -> list[Advisory]:
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        try:
            await page.goto(URL, wait_until="networkidle", timeout=30000)
        except Exception:
            pass  # grab whatever rendered before timeout

        html = await page.content()
        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(" ")

        seen: set[str] = set()
        advisories = []
        for cve in CVE_RE.findall(text):
            cve = cve.upper()
            if cve not in seen:
                seen.add(cve)
                advisories.append(Advisory(
                    url=f"https://vulncheck.com/advisories/{cve.lower()}",
                    cve_ids=[cve],
                ))

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
