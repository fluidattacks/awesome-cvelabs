#!/usr/bin/env python3
"""Claroty Team82 scraper. Outputs data.json.
Source: Sitemap → CVE IDs extracted directly from URL slugs (cve-XXXX-XXXXX format).
Detail pages are JS-rendered; CVE IDs come from URL slug alone.
"""
import re, sys
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Claroty Team82"
URL = "https://claroty.com/team82/disclosure-dashboard"
SITEMAP_URL = "https://claroty.com/sitemap.xml"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


def _get_advisory_urls() -> list[str]:
    seen: set[str] = set()
    urls = []

    try:
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

        for loc in all_locs:
            if "team82" in loc.lower() and "cve-" in loc.lower() and loc not in seen:
                seen.add(loc)
                urls.append(loc)
    except requests.RequestException as e:
        print(f"  Sitemap error: {e}")

    return urls


def scrape() -> list[Advisory]:
    adv_urls = _get_advisory_urls()
    advisories = []
    seen_cves: set[str] = set()

    for url in adv_urls:
        # Extract CVE from URL slug directly
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
