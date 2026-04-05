#!/usr/bin/env python3
"""Orange Cyberdefense scraper — Playwright edition.
Source: GitHub raw README.md — markdown table with CVE IDs and researcher names.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Orange Cyberdefense"
URL = "https://github.com/Orange-Cyberdefense/CVE-repository"
README_URL = "https://raw.githubusercontent.com/Orange-Cyberdefense/CVE-repository/master/README.md"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


async def scrape() -> list[Advisory]:
    async with async_playwright() as p:
        api = await p.request.new_context()
        try:
            resp = await api.get(README_URL)
            content = await resp.text()
        except Exception as e:
            print(f"  Error: {e}")
            await api.dispose()
            return []
        await api.dispose()

    advisories = []
    seen = set()

    for line in content.splitlines():
        cves_in_line = CVE_RE.findall(line)
        if not cves_in_line:
            continue
        cve = cves_in_line[0].upper()
        if cve in seen:
            continue
        seen.add(cve)

        cols = [c.strip() for c in line.split("|") if c.strip()]
        researcher = []
        if len(cols) >= 5:
            candidate = cols[-1] if cols else ""
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
    advisories = [a for a in asyncio.run(scrape()) if a.cve_ids]
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
