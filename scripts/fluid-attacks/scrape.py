#!/usr/bin/env python3
"""Fluid Attacks scraper — Playwright edition.
Source: Framer SPA at /advisories → individual /advisories/<slug> pages.
Fields: CVE ID(s) / Release date / Vendor / Discovered by.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Fluid Attacks"
URL = "https://fluidattacks.com/advisories"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


async def _get_advisory_urls(page) -> list[str]:
    try:
        await page.goto(URL, wait_until="networkidle", timeout=30000)
    except Exception:
        pass

    # Click "Load more" until exhausted — Framer CMS lazy-loads in batches of ~8
    rounds = 0
    while rounds < 100:
        btn = await page.query_selector("text=Load more")
        if not btn:
            break
        await btn.scroll_into_view_if_needed()
        await btn.click()
        await page.wait_for_timeout(3500)
        rounds += 1

    html = await page.content()
    soup = BeautifulSoup(html, "html.parser")
    seen: set[str] = set()
    urls = []
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        m = re.match(r"^\.?/advisories/([^/?#]+)$", href)
        if m and m.group(1) != "advisories":
            full_url = f"https://fluidattacks.com/advisories/{m.group(1)}"
            if full_url not in seen:
                seen.add(full_url)
                urls.append(full_url)
    return urls


async def _parse_page(page, url: str) -> Advisory | None:
    try:
        resp = await page.goto(url, wait_until="networkidle", timeout=30000)
        if resp and resp.status != 200:
            return None
        html = await page.content()
    except Exception:
        return None

    soup = BeautifulSoup(html, "html.parser")
    lines = [l.strip() for l in soup.get_text("\n").splitlines() if l.strip()]

    cves, date_str, vendor, researcher = [], None, [], []

    for i, line in enumerate(lines):
        nxt = lines[i + 1] if i + 1 < len(lines) else ""

        if line == "CVE ID(s)" and nxt:
            cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(nxt)))

        elif line == "Release date" and nxt:
            for fmt in ("%b %d, %Y", "%B %d, %Y"):
                try:
                    dt = datetime.strptime(nxt.strip(), fmt)
                    date_str = dt.strftime("%y/%m/%d")
                    break
                except ValueError:
                    pass

        elif line == "Vendor" and nxt and nxt not in ("Vendor", "Affected product", "Affected version(s)"):
            vendor = [nxt]

        elif line == "Discovered by" and nxt:
            names_raw = re.split(r",\s*| and ", nxt)
            researcher = [n.strip() for n in names_raw if n.strip() and len(n.strip()) < 80]

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
