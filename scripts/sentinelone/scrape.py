#!/usr/bin/env python3
"""SentinelOne scraper. Outputs data.json.
Source: JS-rendered WordPress site. No CVEs accessible from static HTML.
Returns empty advisory list — requires headless browser for full data.
"""
import re, sys
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "SentinelOne"
URL = "https://www.sentinelone.com/labs/our-cves/"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


def scrape() -> list[Advisory]:
    try:
        resp = requests.get(URL, headers=HEADERS, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"  Error: {e}")
        return []

    # JS-rendered: attempt to extract any CVEs from static HTML
    cves = re.findall(r"CVE-\d{4}-\d{4,5}", resp.text)
    seen: set[str] = set()
    advisories = []
    for cve in cves:
        cve = cve.upper()
        if cve not in seen:
            seen.add(cve)
            advisories.append(Advisory(url=f"{URL}#{cve}", cve_ids=[cve]))

    if not advisories:
        print("  NOTE: JS-rendered page returned 0 CVEs — headless browser required for full data")

    return advisories


if __name__ == "__main__":
    advisories = scrape()
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
