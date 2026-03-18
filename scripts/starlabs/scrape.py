#!/usr/bin/env python3
"""Star Labs SG scraper. Outputs data.json.
Source: Sitemap → /advisories/ pages → date, CVE IDs, researchers, vendors.
Page structure has labeled fields: Product / Vendor / Credits in sequential lines.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Star Labs SG"
URL = "https://starlabs.sg"
SITEMAP_URL = "https://starlabs.sg/sitemap.xml"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
DATE_RE = re.compile(r"(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}", re.IGNORECASE)


def _get_advisory_urls() -> list[str]:
    resp = requests.get(SITEMAP_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    locs = re.findall(r"<loc>([^<]+/advisories/[^<]+)</loc>", resp.text)
    seen: set[str] = set()
    urls = []
    for loc in locs:
        if loc.rstrip("/").endswith("/advisories"):
            continue
        if loc not in seen:
            seen.add(loc)
            urls.append(loc)

    def adv_key(u: str) -> tuple:
        m = re.search(r"/advisories/(\d{2})/(\d{2})-(\d+)/", u)
        return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else (0, 0, 0)

    urls.sort(key=adv_key, reverse=True)
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

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(" ".join(lines))))

    # Date: "July 31, 2024 · 5 min · Name"
    date_str = None
    for line in lines[:30]:
        m = DATE_RE.search(line)
        if m:
            try:
                dt = datetime.strptime(m.group(0), "%B %d, %Y")
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass

    # Structured fields: label on one line, value on next
    vendor, researcher = [], []
    for i, line in enumerate(lines):
        if line == "Vendor" and i + 1 < len(lines):
            v = lines[i + 1]
            if v and v not in ("Vendor", "Product", "Severity", "CVE Identifier"):
                vendor = [v]
        elif line in ("Credits", "Credit") and i + 1 < len(lines):
            # Collect researcher names until next section header
            for j in range(i + 1, min(i + 6, len(lines))):
                r_line = lines[j]
                if r_line in ("Summary", "Description", "Timeline", "References", "#"):
                    break
                if r_line and not r_line.startswith("CVE-") and len(r_line) < 80:
                    researcher.append(r_line)

    # Researcher fallback: byline "· Name" in date line
    if not researcher:
        for line in lines[:30]:
            parts = [p.strip() for p in line.split("·")]
            if len(parts) >= 3:
                name = parts[-1].strip()
                if name and len(name) < 50 and not re.search(r"\d min", name):
                    researcher = [name]
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
