#!/usr/bin/env python3
"""Positive Technologies scraper — Playwright edition.
Source: Sitemap → advisory/vulnerability posts → CVE IDs from URL slugs.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Positive Technologies"
URL = "https://ptsecurity.com/ww-en/analytics/threatscape/"
SITEMAP_INDEX = "https://ptsecurity.com/sitemap.xml"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
ADVISORY_KEYWORDS = ["threatscape", "vulnerability", "advisory", "cve-", "vuln"]


async def _get_advisory_urls(api) -> list[str]:
    seen: set[str] = set()
    urls = []

    try:
        resp = await api.get(SITEMAP_INDEX)
        content = await resp.text()
        locs = re.findall(r"<loc>([^<]+)</loc>", content)
    except Exception:
        return []

    sub_sitemaps = [l for l in locs if "sitemap" in l.lower()]
    all_locs = list(locs)

    for sm in sub_sitemaps[:10]:
        try:
            r2 = await api.get(sm)
            sub = await r2.text()
            all_locs.extend(re.findall(r"<loc>([^<]+)</loc>", sub))
        except Exception:
            pass

    for loc in all_locs:
        if any(kw in loc.lower() for kw in ADVISORY_KEYWORDS) and loc not in seen:
            seen.add(loc)
            urls.append(loc)

    return urls


async def scrape() -> list[Advisory]:
    advisories = []
    async with async_playwright() as p:
        api = await p.request.new_context()
        adv_urls = await _get_advisory_urls(api)
        await api.dispose()
        seen_cves: set[str] = set()
        for url in adv_urls:
            cves_in_url = [c.upper() for c in CVE_RE.findall(url)]
            new_cves = [c for c in dict.fromkeys(cves_in_url) if c not in seen_cves]
            for c in new_cves:
                seen_cves.add(c)
            advisories.append(Advisory(url=url, cve_ids=new_cves))
    return advisories


if __name__ == "__main__":
    advisories = [a for a in asyncio.run(scrape()) if a.cve_ids]
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
