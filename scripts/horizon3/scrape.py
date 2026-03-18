#!/usr/bin/env python3
"""Horizon3 scraper. Outputs data.json.
Source: Sitemap → /attack-research/ pages → date, CVE IDs, researchers, vendors.
Vendor extracted from title. Researcher from author byline.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Horizon3"
URL = "https://www.horizon3.ai"
SITEMAP_URL = "https://www.horizon3.ai/sitemap.xml"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
ADVISORY_PATH = "/attack-research/"
DATE_RE = re.compile(
    r"\b((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}|\d{4}-\d{2}-\d{2})\b",
    re.IGNORECASE,
)


def _get_advisory_urls() -> list[str]:
    resp = requests.get(SITEMAP_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    locs = re.findall(r"<loc>([^<]+)</loc>", resp.text)
    sub_sitemaps = [l for l in locs if "sitemap" in l.lower()]
    all_locs = list(locs)
    for sm in sub_sitemaps[:10]:
        try:
            r2 = requests.get(sm, headers=HEADERS, timeout=30)
            if r2.status_code == 200:
                all_locs.extend(re.findall(r"<loc>([^<]+)</loc>", r2.text))
        except requests.RequestException:
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
    """Extract product/vendor name from advisory title.
    E.g. 'CVE-2025-9316 & CVE-2025-11700 N-central 0-Days' → 'N-central'
    """
    # Remove CVE references and get the remaining product name
    cleaned = re.sub(r"CVE-\d{4}-\d+\s*[&,]?\s*", "", title, flags=re.IGNORECASE).strip()
    # Remove trailing noise
    cleaned = re.sub(r"\s*(0-day|0days?|vulnerabilit\w*|advisory|rce|exploit\w*|attack\w*|bypass\w*)\s*$", "", cleaned, flags=re.IGNORECASE).strip(" |-")
    cleaned = re.sub(r"\s*\|.*$", "", cleaned).strip()
    if cleaned and 2 < len(cleaned) < 80:
        return [cleaned]
    return []


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
        for fmt in ("%B %d, %Y", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s, fmt)
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass

    # Researcher: meta author or "By <name>" or author tag
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

    # Vendor from h1
    vendor = []
    h1 = soup.find("h1")
    if h1:
        vendor = _vendor_from_title(h1.get_text(strip=True))

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
