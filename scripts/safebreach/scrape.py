#!/usr/bin/env python3
"""SafeBreach Labs scraper — Playwright edition.
Source: WordPress REST API /wp-json/wp/v2/vulnerability → date, CVE IDs, vendors, researchers.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "SafeBreach Labs"
URL = "https://www.safebreach.com/blog/research/"
API_BASE = "https://www.safebreach.com/wp-json/wp/v2/vulnerability"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


def _wp_date(date_str: str) -> str | None:
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%y/%m/%d")
    except ValueError:
        return None


def _vendor_from_title(title: str) -> list[str]:
    clean = re.sub(r"CVE-\d{4}-\d+[:\s]*", "", title, flags=re.IGNORECASE).strip()
    clean = re.sub(r"\s*(RCE|LPE|SSRF|XSS|SQLI|Auth Bypass|Vulnerability|0-[Dd]ay|Exploit)\s*$", "", clean).strip()
    clean = re.sub(r"^Hacking\s+", "", clean, flags=re.IGNORECASE).strip()
    if clean and 2 < len(clean) < 80:
        return [clean]
    return []


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
                if page_num == 1:
                    total = int(resp.headers.get("x-wp-total") or 0)
                    total_pages = int(resp.headers.get("x-wp-totalpages") or 1)
                    print(f"  Total: {total} posts, {total_pages} pages")
                    if len(data) >= total:
                        break
                if len(data) < 100:
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
        title = BeautifulSoup(post.get("title", {}).get("rendered", ""), "html.parser").get_text()
        content = BeautifulSoup(post.get("content", {}).get("rendered", ""), "html.parser").get_text(" ")

        slug = link.rstrip("/").split("/")[-1]
        cves = [c.upper() for c in CVE_RE.findall(slug + " " + title + " " + content)]
        new_cves = [c for c in dict.fromkeys(cves) if c not in seen_cves]
        for c in new_cves:
            seen_cves.add(c)

        vendor = _vendor_from_title(title)

        researcher = []
        m = re.search(r"\bby\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})", content)
        if m:
            name = m.group(1).strip()
            if name and len(name) < 60:
                researcher = [name]

        advisories.append(Advisory(url=link, date=date_str, cve_ids=new_cves,
                                   researchers=researcher, vendors=vendor))

    return advisories


if __name__ == "__main__":
    advisories = [a for a in asyncio.run(scrape()) if a.cve_ids]
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
