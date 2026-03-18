#!/usr/bin/env python3
"""FortiGuard scraper. Outputs data.json.
Source: JS-rendered SPA. Extracts partial CVE IDs from static HTML only.
Full data requires headless browser.
"""
import re, sys
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "FortiGuard"
URL = "https://www.fortiguard.com/psirt"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


def scrape() -> list[Advisory]:
    try:
        resp = requests.get(URL, headers=HEADERS, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"  Error: {e}")
        return []

    cves = re.findall(r"CVE-\d{4}-\d{4,5}", resp.text)
    seen: set[str] = set()
    advisories = []
    for cve in cves:
        cve = cve.upper()
        if cve not in seen:
            seen.add(cve)
            advisories.append(Advisory(
                url=f"https://www.fortiguard.com/psirt/{cve.lower()}",
                cve_ids=[cve],
            ))

    return advisories


if __name__ == "__main__":
    advisories = scrape()
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
