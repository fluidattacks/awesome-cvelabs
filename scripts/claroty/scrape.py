#!/usr/bin/env python3
"""Claroty Team82 scraper — Playwright edition.
Source: Sitemap → CVE IDs extracted directly from URL slugs (cve-XXXX-XXXXX format).
Detail pages are JS-rendered; CVE IDs come from URL slug alone.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Claroty Team82"
URL = "https://claroty.com/team82/disclosure-dashboard"
SITEMAP_URL = "https://claroty.com/sitemap.xml"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


async def _get_advisory_urls(api) -> list[str]:
    seen: set[str] = set()
    urls = []

    try:
        resp = await api.get(SITEMAP_URL)
        content = await resp.text()
        locs = re.findall(r"<loc>([^<]+)</loc>", content)
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
            if "team82" in loc.lower() and "cve-" in loc.lower() and loc not in seen:
                seen.add(loc)
                urls.append(loc)
    except Exception as e:
        print(f"  Sitemap error: {e}")

    return urls


async def scrape() -> list[Advisory]:
    advisories = []
    async with async_playwright() as p:
        api = await p.request.new_context()
        adv_urls = await _get_advisory_urls(api)
        seen_cves: set[str] = set()
        for url in adv_urls:
            cves_in_url = [c.upper() for c in CVE_RE.findall(url)]
            new_cves = [c for c in dict.fromkeys(cves_in_url) if c not in seen_cves]
            for c in new_cves:
                seen_cves.add(c)
            advisories.append(Advisory(url=url, cve_ids=new_cves))
        await api.dispose()
    return advisories


if __name__ == "__main__":
    advisories = [a for a in asyncio.run(scrape()) if a.cve_ids]
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
