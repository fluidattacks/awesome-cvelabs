#!/usr/bin/env python3
"""Nozomi Networks scraper — Playwright edition.
Source: Sitemap → advisory pages → CVE IDs from URL slugs + page content.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Nozomi Networks"
URL = "https://www.nozominetworks.com/vulnerability-advisories"
SITEMAP_URL = "https://www.nozominetworks.com/sitemap.xml"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


async def _get_advisory_urls(api) -> list[str]:
    seen: set[str] = set()
    urls = []

    try:
        resp = await api.get(SITEMAP_URL)
        content = await resp.text()
        locs = re.findall(r"<loc>([^<]+)</loc>", content)
        for loc in locs:
            if "vulnerabilit" in loc.lower() and loc not in seen:
                seen.add(loc)
                urls.append(loc)
    except Exception:
        pass

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
    if not cves:
        # Fall back to CVEs in URL slug
        cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(url)))

    return Advisory(url=url, cve_ids=cves)


async def scrape() -> list[Advisory]:
    advisories = []
    async with async_playwright() as p:
        api = await p.request.new_context()
        adv_urls = await _get_advisory_urls(api)
        await api.dispose()

        if adv_urls:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            seen_cves: set[str] = set()
            for url in adv_urls:
                adv = await _parse_page(page, url)
                if adv:
                    new_cves = [c for c in adv.cve_ids if c not in seen_cves]
                    for c in new_cves:
                        seen_cves.add(c)
                    advisories.append(Advisory(url=adv.url, cve_ids=new_cves))
            await browser.close()
        else:
            # Fallback: extract CVEs from the index page
            browser = await p.chromium.launch()
            page = await browser.new_page()
            try:
                await page.goto(URL, wait_until="networkidle", timeout=30000)
            except Exception:
                pass
            html = await page.content()
            await browser.close()
            seen: set[str] = set()
            for cve in CVE_RE.findall(html):
                cve = cve.upper()
                if cve not in seen:
                    seen.add(cve)
                    advisories.append(Advisory(url=f"{URL}#{cve.lower()}", cve_ids=[cve]))

    return advisories


if __name__ == "__main__":
    advisories = [a for a in asyncio.run(scrape()) if a.cve_ids]
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
