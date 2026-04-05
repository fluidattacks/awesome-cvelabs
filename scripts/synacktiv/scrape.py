#!/usr/bin/env python3
"""Synacktiv scraper — Playwright edition.
Source: Sitemap → /advisories/ pages → date, CVE IDs, vendors, researchers.
Page structure: Product / Authors / date in labeled lines.
"""
import asyncio, html as html_mod, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Synacktiv"
URL = "https://www.synacktiv.com"
SITEMAP_URL = "https://www.synacktiv.com/sitemap.xml"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
DATE_SLASH = re.compile(r"\b(\d{2}/\d{2}/\d{4})\b")
DATE_ISO = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")


async def _get_advisory_urls(page) -> list[str]:
    try:
        await page.goto(SITEMAP_URL, wait_until="domcontentloaded", timeout=30000)
    except Exception:
        return []
    content = html_mod.unescape(await page.content())
    locs = re.findall(r"<loc>([^<]+/advisories/[^<]+)</loc>", content)
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

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(" ".join(lines))))

    date_str = None
    for line in lines[:20]:
        m = DATE_SLASH.search(line)
        if m:
            try:
                dt = datetime.strptime(m.group(1), "%d/%m/%Y")
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass
    if not date_str:
        for line in lines:
            m = DATE_ISO.search(line)
            if m:
                try:
                    dt = datetime.strptime(m.group(1), "%Y-%m-%d")
                    date_str = dt.strftime("%y/%m/%d")
                    break
                except ValueError:
                    pass

    vendor = []
    for i, line in enumerate(lines):
        if line == "Product" and i + 1 < len(lines):
            v = lines[i + 1]
            if v and v not in ("Severity", "Fixed Version(s)", "Authors", "CVE Number") and len(v) < 100:
                vendor = [v]
            break

    researcher = []
    for i, line in enumerate(lines):
        if line == "Authors" and i + 1 < len(lines):
            for j in range(i + 1, min(i + 6, len(lines))):
                name = lines[j]
                if name in ("Description", "Timeline", "Summary", "Fixed Version(s)", "Severity"):
                    break
                if name and len(name) < 60:
                    researcher.append(name)
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
