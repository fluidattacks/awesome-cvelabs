#!/usr/bin/env python3
"""WithSecure Labs scraper. Outputs data.json.
Source: JS-rendered SPA. No sitemap. Returns empty advisory list.
Requires headless browser for full data.
"""
import re, sys
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "WithSecure Labs"
URL = "https://labs.withsecure.com/advisories"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


def scrape() -> list[Advisory]:
    try:
        resp = requests.get(URL, headers=HEADERS, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"  Error: {e}")
        return []

    # JS-rendered: attempt to extract advisory links or CVEs from static HTML
    adv_links = re.findall(r'href="(/advisories/[^"]+)"', resp.text)
    cves = re.findall(r"CVE-\d{4}-\d{4,5}", resp.text)

    seen: set[str] = set()
    advisories = []

    if adv_links:
        for href in dict.fromkeys(adv_links):
            full_url = "https://labs.withsecure.com" + href
            if full_url not in seen:
                seen.add(full_url)
                advisories.append(Advisory(url=full_url))
    elif cves:
        for cve in cves:
            cve = cve.upper()
            if cve not in seen:
                seen.add(cve)
                advisories.append(Advisory(url=f"{URL}#{cve}", cve_ids=[cve]))
    else:
        print("  NOTE: JS-rendered SPA returned 0 advisories — headless browser required")

    return advisories


if __name__ == "__main__":
    advisories = scrape()
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
