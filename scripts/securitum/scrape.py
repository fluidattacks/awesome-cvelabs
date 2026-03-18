#!/usr/bin/env python3
"""Securitum scraper. Outputs data.json.
Source: insights.html index → individual article pages for CVE IDs.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Securitum"
URL = "https://www.securitum.com"
INDEX_URL = URL + "/insights.html"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
NAV_PAGES = {
    "index.html", "services.html", "web-application-penetration-testing.html",
    "mobile-application-penetration-testing.html", "infrastructure-penetration-testing.html",
    "cloud-security-cloud-assessment.html", "social-engineering.html",
    "ssdlc-implementation.html", "configuration-analysis.html", "osint.html",
    "redteam.html", "insights.html", "about.html", "contact.html", "career.html",
    "desktop-and-console-applications.html", "source-code-review.html",
    "red-teaming.html", "trainings-publications.html", "pricing.html",
    "resources.html", "pentest-chronicles.html", "public-reports.html",
    "partnership.html", "about-us.html", "team-references.html",
    "events.html", "terms-and-conditions.html",
}


def _article_urls() -> list[str]:
    resp = requests.get(INDEX_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    hrefs = list(dict.fromkeys(re.findall(r'href="([^"#?]+\.html)"', resp.text)))
    urls = []
    seen: set[str] = set()
    for href in hrefs:
        if href.startswith("http"):
            continue
        filename = href.lstrip("/").split("/")[-1]
        if filename in NAV_PAGES:
            continue
        full_url = URL + "/" + filename
        if full_url not in seen:
            seen.add(full_url)
            urls.append(full_url)
    return urls


def scrape() -> list[Advisory]:
    article_urls = _article_urls()
    advisories = []
    seen_cves: set[str] = set()

    for art_url in article_urls:
        try:
            resp = requests.get(art_url, headers=HEADERS, timeout=30)
            if resp.status_code != 200:
                continue
        except requests.RequestException:
            continue

        cves = [c.upper() for c in CVE_RE.findall(resp.text)]
        new_cves = [c for c in dict.fromkeys(cves) if c not in seen_cves]
        if new_cves:
            for c in new_cves:
                seen_cves.add(c)
            advisories.append(Advisory(url=art_url, cve_ids=new_cves))
        time.sleep(0.2)

    return advisories


if __name__ == "__main__":
    advisories = scrape()
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
