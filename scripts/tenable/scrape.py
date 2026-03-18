#!/usr/bin/env python3
"""Tenable Research scraper. Outputs data.json.
Source: JS-rendered SPA. Attempts sitemap extraction for research/CVE blog posts.
Full detail requires JS rendering.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Tenable Research"
URL = "https://www.tenable.com/security/research"
SITEMAP_BASE = "https://www.tenable.com/sitemap.xml"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
RESEARCH_KEYWORDS = ["/security/research", "/blog/cve-"]


def _get_advisory_urls() -> list[str]:
    seen: set[str] = set()
    urls = []

    for page in [1, 2]:
        try:
            resp = requests.get(f"{SITEMAP_BASE}?page={page}", headers=HEADERS, timeout=30)
            if resp.status_code != 200:
                continue
            locs = re.findall(r"<loc>([^<]+)</loc>", resp.text)
            for loc in locs:
                if any(k in loc for k in RESEARCH_KEYWORDS) and loc not in seen:
                    seen.add(loc)
                    urls.append(loc)
        except requests.RequestException:
            pass

    # Also try main sitemap
    try:
        resp = requests.get(SITEMAP_BASE, headers=HEADERS, timeout=30)
        if resp.status_code == 200:
            locs = re.findall(r"<loc>([^<]+)</loc>", resp.text)
            sub_sitemaps = [l for l in locs if "sitemap" in l.lower()]
            for sm in sub_sitemaps[:5]:
                try:
                    r2 = requests.get(sm, headers=HEADERS, timeout=30)
                    if r2.status_code == 200:
                        for loc in re.findall(r"<loc>([^<]+)</loc>", r2.text):
                            if any(k in loc for k in RESEARCH_KEYWORDS) and loc not in seen:
                                seen.add(loc)
                                urls.append(loc)
                except requests.RequestException:
                    pass
    except requests.RequestException:
        pass

    return urls


def scrape() -> list[Advisory]:
    # JS-rendered SPA: collect URLs from sitemap only, extract CVEs from URL slug where possible
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
