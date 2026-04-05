#!/usr/bin/env python3
"""Securitum scraper — Playwright edition.
Source: insights.html index → individual article pages for CVE IDs.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Securitum"
URL = "https://www.securitum.com"
INDEX_URL = URL + "/insights.html"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
NAV_PAGES = {
    "index.html", "services.html", "web-application-penetration-testing.html",
    "mobile-application-penetration-testing.html", "infrastructure-penetration-testing.html",
    "cloud-security-cloud-assessment.html", "social-engineering.html",
    "ssdlc-implementation.html", "configuration-analysis.html", "osint.html",
    "redteam.html", "insights.html", "about.html", "contact.html", "career.html",
    "desktop-and-console-applications.html", "source-code-review.html",
    "red-teaming.html", "trainings-publications.html", "pricing.html",
    "resources.html", "pentest-chronicles.html", "public-reports.html",
    "partnership.html", "about-us.html", "team-references.html",
    "events.html", "terms-and-conditions.html",
}


async def _article_urls(page) -> list[str]:
    await page.goto(INDEX_URL, wait_until="networkidle")
    html = await page.content()
    hrefs = list(dict.fromkeys(re.findall(r'href="([^"#?]+\.html)"', html)))
    urls = []
    seen: set[str] = set()
    for href in hrefs:
        if href.startswith("http"):
            continue
        filename = href.lstrip("/").split("/")[-1]
        if filename in NAV_PAGES:
            continue
        full_url = URL + "/" + filename
        if full_url not in seen:
            seen.add(full_url)
            urls.append(full_url)
    return urls


async def scrape() -> list[Advisory]:
    advisories = []
    seen_cves: set[str] = set()

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        article_urls = await _article_urls(page)

        for art_url in article_urls:
            try:
                await page.goto(art_url, wait_until="networkidle", timeout=30000)
                html = await page.content()
            except Exception:
                continue

            cves = [c.upper() for c in CVE_RE.findall(html)]
            new_cves = [c for c in dict.fromkeys(cves) if c not in seen_cves]
            if new_cves:
                for c in new_cves:
                    seen_cves.add(c)
                advisories.append(Advisory(url=art_url, cve_ids=new_cves))

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
