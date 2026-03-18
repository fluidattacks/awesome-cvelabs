#!/usr/bin/env python3
"""Portcullis Labs scraper. Outputs data.json.
Source: Static HTML advisory index — CVE IDs in text.
"""
import re, sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Portcullis Labs"
URL = "https://labs.portcullis.co.uk/advisories/"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
SKIP_PATTERNS = [
    "portcullis.co.uk", "portcullis-security.com", "cisco.com",
    "keyserver.pgp", "google.com", "googleapis.com",
    "twitter.com", "linkedin.com", "facebook.com",
]


def scrape() -> list[Advisory]:
    resp = requests.get(URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    advisories = []
    seen_urls: set[str] = set()
    seen_cves: set[str] = set()

    # Each advisory is typically in a list item with a link and CVE text
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if any(skip in href for skip in SKIP_PATTERNS):
            continue
        if not href.startswith("http"):
            continue
        if href in seen_urls:
            continue

        # Get surrounding text for CVE IDs
        parent_text = a_tag.parent.get_text(" ") if a_tag.parent else a_tag.get_text()
        cves = [c.upper() for c in CVE_RE.findall(parent_text)]
        new_cves = [c for c in cves if c not in seen_cves]
        if not new_cves and not cves:
            continue

        seen_urls.add(href)
        for c in new_cves:
            seen_cves.add(c)

        advisories.append(Advisory(url=href, cve_ids=new_cves or cves))

    # Also catch CVE anchors from the static page if no external links found
    if not advisories:
        all_cves = [c.upper() for c in CVE_RE.findall(resp.text)]
        for cve in dict.fromkeys(all_cves):
            advisories.append(Advisory(url=f"{URL}#{cve}", cve_ids=[cve]))

    return advisories


if __name__ == "__main__":
    advisories = scrape()
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
