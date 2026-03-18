#!/usr/bin/env python3
"""Nozomi Networks scraper. Outputs data.json.
Source: JS-rendered advisory page. Attempts sitemap + static HTML extraction.
Full detail requires headless browser.
"""
import re, sys
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Nozomi Networks"
URL = "https://www.nozominetworks.com/vulnerability-advisories"
SITEMAP_URL = "https://www.nozominetworks.com/sitemap.xml"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


def _get_advisory_urls() -> list[str]:
    seen: set[str] = set()
    urls = []

    try:
        resp = requests.get(SITEMAP_URL, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        locs = re.findall(r"<loc>([^<]+)</loc>", resp.text)
        for loc in locs:
            if "vulnerabilit" in loc.lower() and loc not in seen:
                seen.add(loc)
                urls.append(loc)
    except requests.RequestException:
        pass

    # Fallback: extract CVEs from index page
    if not urls:
        try:
            resp2 = requests.get(URL, headers=HEADERS, timeout=30)
            resp2.raise_for_status()
            cves = re.findall(r"CVE-\d{4}-\d{4,5}", resp2.text)
            for cve in cves:
                cve = cve.upper()
                if cve not in seen:
                    seen.add(cve)
                    urls.append(f"{URL}#{cve.lower()}")
        except requests.RequestException:
            pass

    return urls


def scrape() -> list[Advisory]:
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
