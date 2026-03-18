#!/usr/bin/env python3
"""NCC Group scraper. Outputs data.json.
Source: Sitemap → /technical-advisory/ pages → date, CVE IDs, researchers, vendors.
Vendor extracted from advisory title. Researcher from author byline.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "NCC Group"
URL = "https://www.nccgroup.com"
SITEMAP_URL = "https://www.nccgroup.com/sitemap.xml"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
DATE_RE = re.compile(
    r"\b(\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}|\d{4}-\d{2}-\d{2})\b",
    re.IGNORECASE
)
# "Technical Advisory: <Vendor> <Product> - <Issue>"
TA_RE = re.compile(r"Technical Advisory[:\s]+(.+?)(?:\s*[-–|]|$)", re.IGNORECASE)


def _get_advisory_urls() -> list[str]:
    resp = requests.get(SITEMAP_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    locs = re.findall(
        r"<loc>(https://www\.nccgroup\.com/[^<]+technical-advisory[^<]+)</loc>",
        resp.text,
    )
    seen: set[str] = set()
    urls = []
    for loc in locs:
        if loc not in seen:
            seen.add(loc)
            urls.append(loc)
    return urls


def _parse_page(url: str) -> Advisory | None:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code != 200:
            return None
    except requests.RequestException:
        return None

    soup = BeautifulSoup(resp.text, "html.parser")
    lines = [l.strip() for l in soup.get_text("\n").splitlines() if l.strip()]
    full_text = " ".join(lines)

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(full_text)))

    # Date
    date_str = None
    m = DATE_RE.search(full_text)
    if m:
        s = m.group(1)
        for fmt in ("%d %B %Y", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s, fmt)
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass

    # Vendor: from h1 title "Technical Advisory: <Vendor Product>"
    vendor = []
    h1 = soup.find("h1")
    if h1:
        title = h1.get_text(strip=True)
        m2 = TA_RE.match(title)
        if m2:
            raw = m2.group(1).strip()
            # Take first meaningful word group before dash or hyphen
            product = re.split(r"\s+[-–]\s+", raw)[0].strip()
            if product and len(product) < 100:
                vendor = [product]

    # Researcher: look for author meta tag or byline
    researcher = []
    # meta author
    meta_author = soup.find("meta", {"name": "author"})
    if meta_author and meta_author.get("content"):
        name = meta_author["content"].strip()
        if name and len(name) < 80:
            researcher = [name]
    # Fallback: "Written by" or name after publication date in page
    if not researcher:
        for line in lines:
            m3 = re.match(r"^(?:Written by|Author)[:\s]+(.+)", line, re.IGNORECASE)
            if m3:
                name = m3.group(1).strip()
                if name and len(name) < 80:
                    researcher = [name]
                break

    return Advisory(url=url, date=date_str, cve_ids=cves,
                    researchers=researcher, vendors=vendor)


def scrape() -> list[Advisory]:
    adv_urls = _get_advisory_urls()
    advisories = []
    for url in adv_urls:
        adv = _parse_page(url)
        if adv:
            advisories.append(adv)
        time.sleep(0.15)
    return advisories


if __name__ == "__main__":
    advisories = scrape()
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
