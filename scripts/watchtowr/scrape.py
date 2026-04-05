#!/usr/bin/env python3
"""watchTowr scraper — Playwright edition.
Source: Blog pagination → article pages → date, CVE IDs, researchers, vendors.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "watchTowr"
URL = "https://labs.watchtowr.com"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
SKIP_PREFIXES = ["/tag/", "/author/", "/page/", "/vulnerability-disclosure-policy", "/disclosed-vulnerabilities"]
DATE_RE = re.compile(
    r"\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|"
    r"Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},\s+\d{4}\b",
    re.IGNORECASE,
)


def _is_post_href(href: str) -> bool:
    if not href.startswith("/"):
        return False
    stripped = href.strip("/")
    if "/" in stripped or not stripped:
        return False
    for prefix in SKIP_PREFIXES:
        if href.startswith(prefix):
            return False
    return "#" not in href and "?" not in href


async def _get_advisory_urls(page) -> list[str]:
    seen: set[str] = set()
    urls = []
    page_num = 1
    while True:
        page_url = URL if page_num == 1 else f"{URL}/page/{page_num}/"
        try:
            resp = await page.goto(page_url, wait_until="domcontentloaded", timeout=30000)
            if resp and resp.status == 404:
                break
        except Exception:
            break
        html = await page.content()
        soup = BeautifulSoup(html, "html.parser")
        new_found = False
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if href.startswith(URL):
                href = href[len(URL):]
            if _is_post_href(href):
                full_url = URL + href.rstrip("/")
                if full_url not in seen:
                    seen.add(full_url)
                    urls.append(full_url)
                    new_found = True
        if not new_found:
            break
        page_num += 1
    return urls


def _vendor_from_title(title: str) -> list[str]:
    m = re.search(r"\(([^)]+CVE-\d{4}-\d+[^)]*)\)", title, re.IGNORECASE)
    if m:
        product = re.sub(r"CVE-\d{4}-\d+", "", m.group(1), flags=re.IGNORECASE).strip(" -,")
        if product and len(product) > 2:
            return [product]
    m2 = re.search(r"^(.+?)\s+CVE-\d{4}-\d+", title, re.IGNORECASE)
    if m2:
        product = m2.group(1).strip()
        product = re.sub(r"^(CVE-\d{4}-\d+\s*[&-]?\s*)+", "", product, flags=re.IGNORECASE).strip()
        if product and len(product) > 2 and len(product) < 80:
            return [product]
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

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(" ".join(lines))))
    if not cves:
        return None

    date_str = None
    for line in lines[:20]:
        m = DATE_RE.search(line)
        if m:
            s = m.group(0)
            for fmt in ("%b %d, %Y", "%B %d, %Y"):
                try:
                    dt = datetime.strptime(s, fmt)
                    date_str = dt.strftime("%y/%m/%d")
                    break
                except ValueError:
                    pass
            if date_str:
                break

    researcher = []
    for i, line in enumerate(lines[:30]):
        if line in ("By  —", "By —", "By—") and i + 1 < len(lines):
            name = lines[i + 1].strip(" —")
            if name and len(name) < 60:
                researcher = [name]
            break
        m2 = re.match(r"^By\s+[—–]\s*(.+)", line)
        if m2:
            name = m2.group(1).strip(" —–")
            if name and len(name) < 60:
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
