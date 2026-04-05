#!/usr/bin/env python3
"""Star Labs SG scraper — Playwright edition.
Source: Sitemap → /advisories/ pages → date, CVE IDs, researchers, vendors.
"""
import asyncio, html as html_mod, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Star Labs SG"
URL = "https://starlabs.sg"
SITEMAP_URL = "https://starlabs.sg/sitemap.xml"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
DATE_RE = re.compile(
    r"(January|February|March|April|May|June|July|August|September|October|November|December)"
    r"\s+\d{1,2},\s+\d{4}",
    re.IGNORECASE,
)


async def _get_advisory_urls(page) -> list[str]:
    try:
        await page.goto(SITEMAP_URL, wait_until="domcontentloaded", timeout=30000)
    except Exception:
        return []
    content = html_mod.unescape(await page.content())
    locs = re.findall(r"<loc>([^<]+/advisories/[^<]+)</loc>", content)
    seen: set[str] = set()
    urls = []
    for loc in locs:
        if loc.rstrip("/").endswith("/advisories"):
            continue
        if loc not in seen:
            seen.add(loc)
            urls.append(loc)

    def adv_key(u: str) -> tuple:
        m = re.search(r"/advisories/(\d{2})/(\d{2})-(\d+)/", u)
        return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else (0, 0, 0)

    urls.sort(key=adv_key, reverse=True)
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

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(" ".join(lines))))

    date_str = None
    for line in lines[:30]:
        m = DATE_RE.search(line)
        if m:
            try:
                dt = datetime.strptime(m.group(0), "%B %d, %Y")
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass

    vendor, researcher = [], []
    for i, line in enumerate(lines):
        if line == "Vendor" and i + 1 < len(lines):
            v = lines[i + 1]
            if v and v not in ("Vendor", "Product", "Severity", "CVE Identifier"):
                vendor = [v]
        elif line in ("Credits", "Credit") and i + 1 < len(lines):
            for j in range(i + 1, min(i + 6, len(lines))):
                r_line = lines[j]
                if r_line in ("Summary", "Description", "Timeline", "References", "#"):
                    break
                if r_line and not r_line.startswith("CVE-") and len(r_line) < 80:
                    researcher.append(r_line)

    if not researcher:
        for line in lines[:30]:
            parts = [p.strip() for p in line.split("·")]
            if len(parts) >= 3:
                name = parts[-1].strip()
                if name and len(name) < 50 and not re.search(r"\d min", name):
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
