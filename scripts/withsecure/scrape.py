#!/usr/bin/env python3
"""WithSecure Labs scraper — Playwright edition.
Source: JS-rendered SPA at /advisories → visit each advisory page → CVE IDs, date.
Note: Index page only exposes ~10 most recent advisories (no public full listing).
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "WithSecure Labs"
URL = "https://labs.withsecure.com/advisories"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


async def _get_advisory_urls(page) -> list[str]:
    try:
        await page.goto(URL, wait_until="networkidle", timeout=30000)
    except Exception:
        pass

    html = await page.content()
    soup = BeautifulSoup(html, "html.parser")
    seen: set[str] = set()
    urls = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        # Prefer absolute .html URLs, fall back to relative slugs
        if "/advisories/" in href and href not in (URL, "/advisories"):
            full_url = href if href.startswith("http") else f"https://labs.withsecure.com{href}"
            # Normalize to .html form
            if not full_url.endswith(".html"):
                full_url = full_url + ".html"
            if full_url not in seen and "_jcr_content" not in full_url:
                seen.add(full_url)
                urls.append(full_url)
    return urls


async def _parse_page(page, url: str) -> Advisory | None:
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        if resp and resp.status != 200:
            return None
        html = await page.content()
    except Exception:
        return None

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

    return Advisory(url=url, date=date_str, cve_ids=cves)


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
