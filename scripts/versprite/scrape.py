#!/usr/bin/env python3
"""VerSprite scraper — Playwright edition.
Source: WordPress REST API /wp-json/wp/v2/advisories — date, CVE IDs from content.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "VerSprite"
URL = "https://versprite.com/advisories/"
API_BASE = "https://versprite.com/wp-json/wp/v2/advisories"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


def _wp_date(date_str: str) -> str | None:
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%y/%m/%d")
    except ValueError:
        return None


async def scrape() -> list[Advisory]:
    all_posts = []
    async with async_playwright() as p:
        api = await p.request.new_context()
        page_num = 1
        while True:
            try:
                resp = await api.get(API_BASE, params={"per_page": 100, "page": page_num})
                if resp.status == 400:
                    break
                if resp.status != 200:
                    break
                data = await resp.json()
                if not data:
                    break
                all_posts.extend(data)
                total_pages = int(resp.headers.get("x-wp-totalpages") or 1)
                if page_num >= total_pages:
                    break
                page_num += 1
            except Exception as e:
                print(f"  Error page {page_num}: {e}")
                break
        await api.dispose()

    advisories = []
    seen_cves: set[str] = set()

    for post in all_posts:
        link = post.get("link") or post.get("guid", {}).get("rendered", "")
        if not link:
            continue

        date_str = _wp_date(post.get("date", ""))
        content = post.get("content", {}).get("rendered", "") + " " + post.get("title", {}).get("rendered", "")
        cves = [c.upper() for c in CVE_RE.findall(content)]
        new_cves = [c for c in dict.fromkeys(cves) if c not in seen_cves]
        for c in new_cves:
            seen_cves.add(c)

        advisories.append(Advisory(
            url=link,
            date=date_str,
            cve_ids=new_cves,
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
