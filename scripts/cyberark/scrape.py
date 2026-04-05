#!/usr/bin/env python3
"""CyberArk Labs scraper — Playwright edition.
Source: Static HTML table with CVE, vendor, researcher, date columns.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "CyberArk Labs"
URL = "https://labs.cyberark.com/cyberark-labs-security-advisories/"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
DATE_PATTERNS = [
    (re.compile(r"(\w+ \d{1,2},?\s*\d{4})"), "%B %d, %Y"),
    (re.compile(r"(\d{4}-\d{2}-\d{2})"), "%Y-%m-%d"),
]


def _parse_cell_date(text: str) -> str | None:
    text = text.strip()
    for pat, fmt in DATE_PATTERNS:
        m = pat.search(text)
        if m:
            try:
                dt = datetime.strptime(m.group(1).replace(",", ""), fmt.replace(",", ""))
                return dt.strftime("%y/%m/%d")
            except ValueError:
                pass
    return None


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
        await browser.close()

    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table", {"id": "tableOne"})
    if not table:
        return []

    advisories = []
    seen: set[str] = set()

    for row in table.find_all("tr")[1:]:
        cells = row.find_all("td")
        if len(cells) < 9:
            continue

        cve_text = cells[2].get_text(strip=True)
        cves_found = CVE_RE.findall(cve_text)
        if not cves_found:
            continue

        cve = cves_found[0].upper()
        if cve in seen:
            continue
        seen.add(cve)

        vendor = cells[3].get_text(strip=True)
        researcher = cells[6].get_text(strip=True)
        date_str = None
        for ci in [0, 1, 7, 8]:
            if ci < len(cells):
                date_str = _parse_cell_date(cells[ci].get_text(strip=True))
                if date_str:
                    break

        advisories.append(Advisory(
            url=f"{URL}#{cve}",
            date=date_str,
            cve_ids=[cve],
            researchers=[researcher] if researcher else [],
            vendors=[vendor] if vendor else [],
        ))

    return advisories


if __name__ == "__main__":
    advisories = [a for a in asyncio.run(scrape()) if a.cve_ids]
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
