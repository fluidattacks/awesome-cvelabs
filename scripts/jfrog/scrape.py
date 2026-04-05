#!/usr/bin/env python3
"""JFrog Security Research scraper — Playwright edition.
Source: Sitemap → /vulnerabilities/ pages → date, CVE IDs, researchers, vendors.
Page structure: Component / Discovered By / Published date in sequential lines.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "JFrog Security Research"
URL = "https://research.jfrog.com"
SITEMAP_URL = "https://research.jfrog.com/sitemap.xml"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
PUB_RE = re.compile(r"Published\s+(\d{1,2}\s+\w+,?\s+\d{4})", re.IGNORECASE)


def _extract_jfsa_id(url: str) -> tuple:
    m = re.search(r"jfsa-(\d{4})-(\d+)", url, re.IGNORECASE)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


async def _get_advisory_urls(api) -> list[str]:
    try:
        resp = await api.get(SITEMAP_URL)
        content = await resp.text()
    except Exception:
        return []
    locs = re.findall(r"<loc>(https://research\.jfrog\.com[^<]+)</loc>", content)
    seen: set[str] = set()
    urls = []
    for url in locs:
        slug = url.rstrip("/").split("/")[-1]
        if "/vulnerabilities/" in url and slug != "vulnerabilities" and url not in seen:
            seen.add(url)
            urls.append(url)
    urls.sort(key=_extract_jfsa_id, reverse=True)
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
    full_text = " ".join(lines)

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(full_text)))

    date_str = None
    m = PUB_RE.search(full_text)
    if m:
        s = m.group(1).replace(",", "").strip()
        for fmt in ("%d %b %Y", "%d %B %Y"):
            try:
                dt = datetime.strptime(s, fmt)
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass

    researcher = []
    for i, line in enumerate(lines):
        if line in ("Discovered By", "Discovered by"):
            if i + 1 < len(lines):
                name = lines[i + 1]
                if name and len(name) < 80 and not name.startswith("of the"):
                    researcher = [name]
            break

    vendor = []
    for i, line in enumerate(lines):
        if line == "Component" and i + 1 < len(lines):
            v = lines[i + 1]
            if v and len(v) < 80:
                vendor = [v]
            break

    return Advisory(url=url, date=date_str, cve_ids=cves,
                    researchers=researcher, vendors=vendor)


async def scrape() -> list[Advisory]:
    advisories = []
    async with async_playwright() as p:
        api = await p.request.new_context()
        browser = await p.chromium.launch()
        page = await browser.new_page()
        adv_urls = await _get_advisory_urls(api)
        for url in adv_urls:
            adv = await _parse_page(page, url)
            if adv:
                advisories.append(adv)
        await browser.close()
        await api.dispose()
    return advisories


if __name__ == "__main__":
    advisories = [a for a in asyncio.run(scrape()) if a.cve_ids]
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
