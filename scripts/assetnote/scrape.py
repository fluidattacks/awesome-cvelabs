#!/usr/bin/env python3
"""Assetnote scraper. Outputs data.json.
Source: /resources/research/?page=N → each article → date, CVE IDs, researchers, vendors.
Vendor extracted from title (product being analyzed). Researcher from byline.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Assetnote"
URL = "https://www.assetnote.io"
INDEX_PATH = "/resources/research"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
DATE_RE = re.compile(
    r"\b((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}|\d{4}-\d{2}-\d{2})\b",
    re.IGNORECASE,
)


def _extract_research_links(html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    found = []
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if (href.startswith("/resources/research/") and
                href.rstrip("/") != INDEX_PATH.rstrip("/")):
            found.append(href)
    return found


def _get_advisory_urls() -> list[str]:
    seen: set[str] = set()
    urls = []
    page = 1
    while True:
        page_url = f"{URL}{INDEX_PATH}/" if page == 1 else f"{URL}{INDEX_PATH}/?page={page}"
        try:
            resp = requests.get(page_url, headers=HEADERS, timeout=30)
            if resp.status_code == 404:
                break
            resp.raise_for_status()
        except requests.RequestException:
            break
        links = _extract_research_links(resp.text)
        if not links:
            break
        new_found = False
        for href in links:
            full_url = URL + href
            if full_url not in seen:
                seen.add(full_url)
                urls.append(full_url)
                new_found = True
        if not new_found:
            break
        page += 1
        time.sleep(0.1)
    return urls


def _vendor_from_title(title: str) -> list[str]:
    """Extract product/vendor name from title.
    E.g. 'Analyzing the Next.js Middleware Bypass (CVE-2025-29927)' → 'Next.js'
    """
    # Pattern: product name followed by CVE in parens
    m = re.search(r"(?:in|of|for|–|-)\s+([A-Za-z0-9][A-Za-z0-9\.\s\-_/]+?)\s+(?:\(CVE|CVE-)", title, re.IGNORECASE)
    if m:
        product = m.group(1).strip()
        if product and 2 < len(product) < 60:
            return [product]
    # Fallback: word groups before CVE
    m2 = re.search(r"([A-Z][A-Za-z0-9\.\-\s]+?)\s+(?:\()?CVE-\d{4}-\d+", title)
    if m2:
        product = m2.group(1).strip()
        if product and 2 < len(product) < 60:
            return [product]
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
    m = DATE_RE.search(full_text[:2000])
    if m:
        s = m.group(1).replace(",", "")
        for fmt in ("%B %d %Y", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s, fmt)
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass

    # Researcher: meta author or byline
    researcher = []
    meta_author = soup.find("meta", {"name": "author"})
    if meta_author and meta_author.get("content"):
        name = meta_author["content"].strip()
        if name and len(name) < 80:
            researcher = [name]
    if not researcher:
        for line in lines[:50]:
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
