#!/usr/bin/env python3
"""Source Incite scraper. Outputs data.json.
Source: /advisories/ listing → each advisory page → date, CVE IDs, researchers, vendors.
Page structure uses labeled fields: CVE ID / Affected Vendors / Affected Products / Credit.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Source Incite"
URL = "https://srcincite.io"
INDEX_URL = URL + "/advisories/"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
# "2024-01-15 – Release of advisory"
RELEASE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})\s*[–-]\s*Release of advisory", re.IGNORECASE)


def _get_advisory_urls() -> list[str]:
    resp = requests.get(INDEX_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    seen: set[str] = set()
    urls = []
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if re.match(r"^src-\d{4}-\d+$", href, re.IGNORECASE):
            full_url = INDEX_URL + href
        elif re.match(r"^/advisories/src-\d{4}-\d+/?$", href, re.IGNORECASE):
            full_url = URL + href.rstrip("/")
        else:
            continue
        if full_url not in seen:
            seen.add(full_url)
            urls.append(full_url)
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
    full_text = "\n".join(lines)

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(full_text)))

    # Date: "YYYY-MM-DD – Release of advisory" in Disclosure Timeline
    date_str = None
    m = RELEASE_RE.search(full_text)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%Y-%m-%d")
            date_str = dt.strftime("%y/%m/%d")
        except ValueError:
            pass

    # Vendor: "Affected Vendors:\n<vendor>"
    vendor = []
    for i, line in enumerate(lines):
        if line in ("Affected Vendors:", "Affected Vendor:") and i + 1 < len(lines):
            v = lines[i + 1].strip()
            if v and v not in ("Affected Products:", "Vulnerability Details:") and len(v) < 80:
                vendor = [v]
            break

    # Researcher: "Credit:\nThis vulnerability was discovered by <Name> of Source Incite"
    researcher = []
    for i, line in enumerate(lines):
        if line == "Credit:" and i + 1 < len(lines):
            credit_line = lines[i + 1]
            m2 = re.search(r"discovered by\s+(.+?)(?:\s+of\s+|\s*$)", credit_line, re.IGNORECASE)
            if m2:
                name = m2.group(1).strip()
                if name and len(name) < 80:
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
