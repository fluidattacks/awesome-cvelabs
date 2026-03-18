#!/usr/bin/env python3
"""JFrog Security Research scraper. Outputs data.json.
Source: Sitemap → /vulnerabilities/ pages → date, CVE IDs, researchers, vendors.
Page structure: Component / Discovered By / Published date in sequential lines.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "JFrog Security Research"
URL = "https://research.jfrog.com"
SITEMAP_URL = "https://research.jfrog.com/sitemap.xml"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
# "Published 9 Feb, 2026 | Last updated..."
PUB_RE = re.compile(r"Published\s+(\d{1,2}\s+\w+,?\s+\d{4})", re.IGNORECASE)


def _extract_jfsa_id(url: str) -> tuple:
    m = re.search(r"jfsa-(\d{4})-(\d+)", url, re.IGNORECASE)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def _get_advisory_urls() -> list[str]:
    resp = requests.get(SITEMAP_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    locs = re.findall(r"<loc>(https://research\.jfrog\.com[^<]+)</loc>", resp.text)
    seen: set[str] = set()
    urls = []
    for url in locs:
        slug = url.rstrip("/").split("/")[-1]
        if "/vulnerabilities/" in url and slug != "vulnerabilities" and url not in seen:
            seen.add(url)
            urls.append(url)
    urls.sort(key=_extract_jfsa_id, reverse=True)
    return urls


def _parse_page(url: str) -> Advisory | None:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code != 200:
            return None
    except requests.RequestException:
        return None

    soup = BeautifulSoup(resp.text, "html.parser")
    lines = [l.strip() for l in soup.get_text("\n").splitlines() if l.strip()]
    full_text = " ".join(lines)

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(full_text)))

    # Date: "Published 9 Feb, 2026"
    date_str = None
    m = PUB_RE.search(full_text)
    if m:
        s = m.group(1).replace(",", "").strip()
        for fmt in ("%d %b %Y", "%d %B %Y"):
            try:
                dt = datetime.strptime(s, fmt)
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass

    # Researcher: "Discovered By\n<name>\nof the JFrog..."
    researcher = []
    for i, line in enumerate(lines):
        if line in ("Discovered By", "Discovered by"):
            if i + 1 < len(lines):
                name = lines[i + 1]
                if name and len(name) < 80 and not name.startswith("of the"):
                    researcher = [name]
            break

    # Vendor/Component: "Component\n<value>"
    vendor = []
    for i, line in enumerate(lines):
        if line == "Component" and i + 1 < len(lines):
            v = lines[i + 1]
            if v and len(v) < 80:
                vendor = [v]
            break

    return Advisory(url=url, date=date_str, cve_ids=cves,
                    researchers=researcher, vendors=vendor)


def scrape() -> list[Advisory]:
    adv_urls = _get_advisory_urls()
    advisories = []
    for url in adv_urls:
        adv = _parse_page(url)
        if adv:
            advisories.append(adv)
        time.sleep(0.15)
    return advisories


if __name__ == "__main__":
    advisories = scrape()
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
