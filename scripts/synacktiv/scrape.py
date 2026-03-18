#!/usr/bin/env python3
"""Synacktiv scraper. Outputs data.json.
Source: Sitemap → /advisories/ pages → date, CVE IDs, vendors, researchers.
Page structure: Product / Authors / date in labeled lines.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Synacktiv"
URL = "https://www.synacktiv.com"
SITEMAP_URL = "https://www.synacktiv.com/sitemap.xml"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
# Date formats: "12/12/2025" or "2025-12-12"
DATE_SLASH = re.compile(r"\b(\d{2}/\d{2}/\d{4})\b")
DATE_ISO = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")


def _get_advisory_urls() -> list[str]:
    resp = requests.get(SITEMAP_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    locs = re.findall(r"<loc>([^<]+/advisories/[^<]+)</loc>", resp.text)
    seen: set[str] = set()
    urls = []
    for loc in locs:
        if loc not in seen:
            seen.add(loc)
            urls.append(loc)
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

    # Date: DD/MM/YYYY appears near top after title
    date_str = None
    for line in lines[:20]:
        m = DATE_SLASH.search(line)
        if m:
            try:
                dt = datetime.strptime(m.group(1), "%d/%m/%Y")
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass
    if not date_str:
        for line in lines:
            m = DATE_ISO.search(line)
            if m:
                try:
                    dt = datetime.strptime(m.group(1), "%Y-%m-%d")
                    date_str = dt.strftime("%y/%m/%d")
                    break
                except ValueError:
                    pass

    # Vendor: "Product\n<value>"
    vendor = []
    for i, line in enumerate(lines):
        if line == "Product" and i + 1 < len(lines):
            v = lines[i + 1]
            if v and v not in ("Severity", "Fixed Version(s)", "Authors", "CVE Number") and len(v) < 100:
                vendor = [v]
            break

    # Researchers: "Authors\n<name1>\n<name2>..."
    researcher = []
    for i, line in enumerate(lines):
        if line == "Authors" and i + 1 < len(lines):
            for j in range(i + 1, min(i + 6, len(lines))):
                name = lines[j]
                if name in ("Description", "Timeline", "Summary", "Fixed Version(s)", "Severity"):
                    break
                if name and len(name) < 60:
                    researcher.append(name)
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
