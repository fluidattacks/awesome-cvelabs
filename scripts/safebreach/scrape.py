#!/usr/bin/env python3
"""SafeBreach Labs scraper. Outputs data.json.
Source: WordPress REST API /wp-json/wp/v2/vulnerability → date, CVE IDs, vendors, researchers.
Vendor and researcher extracted from post title and content.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "SafeBreach Labs"
URL = "https://www.safebreach.com/blog/research/"
API_BASE = "https://www.safebreach.com/wp-json/wp/v2/vulnerability"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


def _wp_date(date_str: str) -> str | None:
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%y/%m/%d")
    except ValueError:
        return None


def _vendor_from_title(title: str) -> list[str]:
    """Extract product name from post title."""
    # "Hacking Microsoft Copilot" → "Microsoft Copilot"
    # "CVE-2024-XXXX: Product Name RCE" → "Product Name"
    clean = re.sub(r"CVE-\d{4}-\d+[:\s]*", "", title, flags=re.IGNORECASE).strip()
    # Remove trailing attack type words
    clean = re.sub(r"\s*(RCE|LPE|SSRF|XSS|SQLI|Auth Bypass|Vulnerability|0-[Dd]ay|Exploit)\s*$", "", clean).strip()
    # Remove "Hacking " prefix
    clean = re.sub(r"^Hacking\s+", "", clean, flags=re.IGNORECASE).strip()
    if clean and 2 < len(clean) < 80:
        return [clean]
    return []


def scrape() -> list[Advisory]:
    all_posts = []
    page = 1
    while True:
        try:
            resp = requests.get(API_BASE,
                                params={"per_page": 100, "page": page},
                                headers=HEADERS, timeout=30)
            if resp.status_code == 400:
                break
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"  Error page {page}: {e}")
            break
        data = resp.json()
        if not data:
            break
        all_posts.extend(data)
        if page == 1:
            total = int(resp.headers.get("X-WP-Total", 0))
            total_pages = int(resp.headers.get("X-WP-TotalPages", 1))
            print(f"  Total: {total} posts, {total_pages} pages")
            if len(data) >= total:
                break
        if len(data) < 100:
            break
        page += 1
        time.sleep(0.1)

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

        # Researcher: look for "by <Name>" in content or author field
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
    advisories = scrape()
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
