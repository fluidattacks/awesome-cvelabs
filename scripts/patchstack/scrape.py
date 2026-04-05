#!/usr/bin/env python3
"""Patchstack scraper — Playwright edition.
Source: /category/security-advisories/page/N/ pagination → each post → date, CVE IDs.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Patchstack"
URL = "https://patchstack.com"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


async def _get_advisory_urls(page) -> list[str]:
    seen: set[str] = set()
    urls = []
    pg = 1

    while True:
        page_url = (
            URL + "/category/security-advisories/"
            if pg == 1
            else URL + f"/category/security-advisories/page/{pg}/"
        )
        try:
            resp = await page.goto(page_url, wait_until="domcontentloaded", timeout=30000)
            if resp and resp.status == 404:
                break
            if not resp or resp.status != 200:
                break
        except Exception:
            break

        html = await page.content()
        soup = BeautifulSoup(html, "html.parser")
        new_found = False
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if (href.startswith(URL + "/") or href.startswith("/")) and \
               "security-advis" not in href and "/page/" not in href and \
               "/category/" not in href and "/tag/" not in href:
                full_url = href if href.startswith("http") else URL + href
                if full_url.startswith(URL) and full_url not in seen and full_url != URL + "/":
                    seen.add(full_url)
                    urls.append(full_url)
                    new_found = True

        if not new_found:
            break
        pg += 1

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
    if not cves:
        return None

    date_str = None
    time_tag = soup.find("time")
    if time_tag:
        dt_attr = time_tag.get("datetime", "") or time_tag.get_text(strip=True)
        try:
            dt = datetime.fromisoformat(dt_attr[:10])
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
