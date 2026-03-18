#!/usr/bin/env python3
"""Core Security Core Labs scraper. Outputs data.json.
Source: Returns 403 Forbidden. Advisory page not publicly accessible.
Returns empty advisory list.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Core Security Core Labs"
URL = "https://www.coresecurity.com/core-labs/advisories"


def scrape() -> list[Advisory]:
    print("  NOTE: Core Security returns 403 Forbidden — advisory page is blocked")
    return []


if __name__ == "__main__":
    advisories = scrape()
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
