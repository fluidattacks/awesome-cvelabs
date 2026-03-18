#!/usr/bin/env python3
"""Integrity Labs scraper. Outputs data.json.
Source: Sitemap → /advisories/ pages → date, CVE IDs, researchers, vendors.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Integrity Labs"
URL = "https://labs.integrity.pt"
SITEMAP_URL = "https://labs.integrity.pt/sitemap.xml"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


def _get_advisory_urls() -> list[str]:
    resp = requests.get(SITEMAP_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    locs = re.findall(r"<loc>([^<]+/advisories/[^<]+)</loc>", resp.text)
    seen: set[str] = set()
    urls = []
    for loc in locs:
        if loc.rstrip("/").endswith("/advisories"):
            continue
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
    text = soup.get_text(" ")

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(text)))

    # Date
    date_str = None
    time_tag = soup.find("time")
    if time_tag:
        dt_attr = time_tag.get("datetime", "") or time_tag.get_text(strip=True)
        try:
            dt = datetime.fromisoformat(dt_attr[:10])
            date_str = dt.strftime("%y/%m/%d")
        except ValueError:
            pass
    if not date_str:
        m = re.search(r"(\d{4}-\d{2}-\d{2})", text)
        if m:
            try:
                dt = datetime.strptime(m.group(1), "%Y-%m-%d")
                date_str = dt.strftime("%y/%m/%d")
            except ValueError:
                pass

    # Researchers
    researchers = []
    disc_m = re.search(r"(?:Researcher|Discovered|Author|Found)[:\s]+([^\n,\.]{3,50})", text, re.IGNORECASE)
    if disc_m:
        name = disc_m.group(1).strip()
        if name and len(name) < 60:
            researchers = [name]

    # Vendors
    vendors = []
    vendor_m = re.search(r"(?:Vendor|Affected Vendor)[:\s]+([^\n,\.]{2,40})", text, re.IGNORECASE)
    if vendor_m:
        v = vendor_m.group(1).strip()
        if v:
            vendors = [v]

    return Advisory(url=url, date=date_str, cve_ids=cves, researchers=researchers, vendors=vendors)


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
