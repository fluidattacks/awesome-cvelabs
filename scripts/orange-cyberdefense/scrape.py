#!/usr/bin/env python3
"""Orange Cyberdefense scraper. Outputs data.json.
Source: GitHub raw README.md — markdown table with CVE IDs and researcher names.
"""
import re, sys
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Orange Cyberdefense"
URL = "https://github.com/Orange-Cyberdefense/CVE-repository"
README_URL = "https://raw.githubusercontent.com/Orange-Cyberdefense/CVE-repository/master/README.md"

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
# Table row format: | [CVE-XXXX-XXXXX] | ... | Researcher Name | ...
ROW_RE = re.compile(
    r"\|\s*\[?(CVE-\d{4}-\d+)\]?[^\|]*\|[^\|]*\|[^\|]*\|[^\|]*\|([^\|]*)\|",
    re.IGNORECASE
)


def scrape() -> list[Advisory]:
    resp = requests.get(README_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    content = resp.text

    advisories = []
    seen = set()

    # Parse markdown table rows for CVE + researcher
    for line in content.splitlines():
        cves_in_line = CVE_RE.findall(line)
        if not cves_in_line:
            continue
        cve = cves_in_line[0].upper()
        if cve in seen:
            continue
        seen.add(cve)

        # Try to extract researcher from the line
        # Typical format: | [CVE-2025-XXXXX][CVE-...] | vendor | product | ... | researcher |
        cols = [c.strip() for c in line.split("|") if c.strip()]
        researcher = []
        if len(cols) >= 5:
            # Last or second-to-last column often has researcher
            candidate = cols[-1] if cols else ""
            # Skip if it looks like a CVE or URL
            if candidate and not CVE_RE.match(candidate) and "http" not in candidate:
                researcher = [candidate]

        anchor = cve.lower()
        adv_url = f"{URL}#{anchor}"
        advisories.append(Advisory(
            url=adv_url,
            cve_ids=[cve],
            researchers=researcher,
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
