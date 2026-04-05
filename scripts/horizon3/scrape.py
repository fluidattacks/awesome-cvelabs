#!/usr/bin/env python3
"""Horizon3 scraper — Playwright edition.
Source: Sitemap (multi-level) → /attack-research/ pages → date, CVE IDs, researchers, vendors.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Horizon3"
URL = "https://www.horizon3.ai"
SITEMAP_URL = "https://www.horizon3.ai/sitemap.xml"
ADVISORY_PATH = "/attack-research/"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
DATE_RE = re.compile(
    r"\b((?:January|February|March|April|May|June|July|August|September|October|"
    r"November|December)\s+\d{1,2},\s+\d{4}|\d{4}-\d{2}-\d{2})\b",
    re.IGNORECASE,
)


async def _get_advisory_urls(api) -> list[str]:
    """Fetch sitemap via raw HTTP (bypasses XSL browser rendering)."""
    try:
        resp = await api.get(SITEMAP_URL)
        content = await resp.text()
    except Exception:
        return []
    locs = re.findall(r"<loc>([^<]+)</loc>", content)
    sub_sitemaps = [l for l in locs if "sitemap" in l.lower()]
    all_locs = list(locs)
    for sm in sub_sitemaps[:10]:
        try:
            r2 = await api.get(sm)
            sub = await r2.text()
            all_locs.extend(re.findall(r"<loc>([^<]+)</loc>", sub))
        except Exception:
            pass
    seen: set[str] = set()
    urls = []
    for loc in all_locs:
        if ADVISORY_PATH in loc and "sitemap" not in loc.lower() and loc not in seen:
            seen.add(loc)
            urls.append(loc)
    urls.sort(reverse=True)
    return urls


def _vendor_from_title(title: str) -> list[str]:
    cleaned = re.sub(r"CVE-\d{4}-\d+\s*[&,]?\s*", "", title, flags=re.IGNORECASE).strip()
    cleaned = re.sub(
        r"\s*(0-day|0days?|vulnerabilit\w*|advisory|rce|exploit\w*|attack\w*|bypass\w*)\s*$",
        "", cleaned, flags=re.IGNORECASE,
    ).strip(" |-")
    cleaned = re.sub(r"\s*\|.*$", "", cleaned).strip()
    if cleaned and 2 < len(cleaned) < 80:
        return [cleaned]
    return []


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
    m = DATE_RE.search(full_text)
    if m:
        s = m.group(1)
        for fmt in ("%B %d, %Y", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s, fmt)
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass

    researcher = []
    meta_author = soup.find("meta", {"name": "author"})
    if meta_author and meta_author.get("content"):
        name = meta_author["content"].strip()
        if name and len(name) < 80:
            researcher = [name]
    if not researcher:
        for line in lines[:40]:
            m2 = re.match(r"^(?:By|Author)[:\s]+(.+)", line, re.IGNORECASE)
            if m2:
                name = m2.group(1).strip()
                if name and len(name) < 80:
                    researcher = [name]
                break

    vendor = []
    h1 = soup.find("h1")
    if h1:
        vendor = _vendor_from_title(h1.get_text(strip=True))

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
