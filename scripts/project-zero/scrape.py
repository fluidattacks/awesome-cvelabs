#!/usr/bin/env python3
"""Google Project Zero scraper — Playwright edition.
Source: Project Zero blog Blogger JSON feed → post titles/content → CVE IDs, dates.
Note: Monorail issue tracker was migrated to Google Issue Tracker (no public API).
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Google Project Zero"
URL = "https://googleprojectzero.blogspot.com/"
BLOG_ID = "4838136820032157985"
FEED_BASE = f"https://googleprojectzero.blogspot.com/feeds/posts/default"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
MAX_PAGES = 20  # up to 1000 posts


async def scrape() -> list[Advisory]:
    advisories = []
    seen_cves: set[str] = set()

    async with async_playwright() as p:
        api = await p.request.new_context()
        start = 1
        per_page = 50

        # First: get total item count from the feed metadata
        try:
            meta_resp = await api.get(FEED_BASE, params={"alt": "json", "max-results": 1})
            meta = await meta_resp.json()
            total = int(meta.get("feed", {}).get("openSearch$totalResults", {}).get("$t", 0))
            print(f"  Blog total posts: {total}")
        except Exception:
            total = MAX_PAGES * per_page

        while start <= total + 1:
            try:
                resp = await api.get(
                    FEED_BASE,
                    params={"alt": "json", "max-results": per_page, "start-index": start},
                )
                if resp.status != 200:
                    break
                data = await resp.json()
            except Exception as e:
                print(f"  Feed error at start={start}: {e}")
                break

            entries = data.get("feed", {}).get("entry", [])
            if not entries:
                break

            for entry in entries:
                title = entry.get("title", {}).get("$t", "")
                content = entry.get("content", {}).get("$t", "") or \
                          entry.get("summary", {}).get("$t", "")
                link_obj = next((l for l in entry.get("link", []) if l.get("rel") == "alternate"), None)
                post_url = link_obj["href"] if link_obj else URL

                date_str = None
                pub = entry.get("published", {}).get("$t", "")
                if pub:
                    try:
                        dt = datetime.fromisoformat(pub[:10])
                        date_str = dt.strftime("%y/%m/%d")
                    except ValueError:
                        pass

                cves = [c.upper() for c in CVE_RE.findall(title + " " + content)]
                new_cves = [c for c in dict.fromkeys(cves) if c not in seen_cves]
                for c in new_cves:
                    seen_cves.add(c)

                if new_cves or post_url != URL:
                    advisories.append(Advisory(url=post_url, date=date_str, cve_ids=new_cves))

            start += per_page

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
