#!/usr/bin/env python3
"""Positive Technologies scraper. Outputs data.json.
Source: JS-rendered site. Uses sitemap to find advisory/vulnerability posts.
Full CVE detail requires JS rendering.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Positive Technologies"
URL = "https://ptsecurity.com/ww-en/analytics/threatscape/"
SITEMAP_INDEX = "https://ptsecurity.com/sitemap.xml"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
ADVISORY_KEYWORDS = ["threatscape", "vulnerability", "advisory", "cve-", "vuln"]


def _get_advisory_urls() -> list[str]:
    seen: set[str] = set()
    urls = []

    try:
        resp = requests.get(SITEMAP_INDEX, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        locs = re.findall(r"<loc>([^<]+)</loc>", resp.text)
    except requests.RequestException:
        return []

    sub_sitemaps = [l for l in locs if "sitemap" in l.lower()]
    all_locs = list(locs)

    for sm in sub_sitemaps[:10]:
        try:
            r2 = requests.get(sm, headers=HEADERS, timeout=30)
            if r2.status_code == 200:
                all_locs.extend(re.findall(r"<loc>([^<]+)</loc>", r2.text))
        except requests.RequestException:
            pass

    for loc in all_locs:
        if any(kw in loc.lower() for kw in ADVISORY_KEYWORDS) and loc not in seen:
            seen.add(loc)
            urls.append(loc)

    return urls


def scrape() -> list[Advisory]:
    # JS-rendered: collect URLs from sitemap only, extract CVEs from URL slug where possible
    adv_urls = _get_advisory_urls()
    advisories = []
    seen_cves: set[str] = set()
    for url in adv_urls:
        cves_in_url = [c.upper() for c in CVE_RE.findall(url)]
        new_cves = [c for c in dict.fromkeys(cves_in_url) if c not in seen_cves]
        for c in new_cves:
            seen_cves.add(c)
        advisories.append(Advisory(url=url, cve_ids=new_cves))
    return advisories


if __name__ == "__main__":
    advisories = scrape()
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
