#!/usr/bin/env python3
"""watchTowr scraper. Outputs data.json.
Source: Blog pagination → article pages → date, CVE IDs, researchers, vendors.
Researcher: "By — Name —" byline. Vendor: extracted from title/h1.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "watchTowr"
URL = "https://labs.watchtowr.com"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
SKIP_PREFIXES = ["/tag/", "/author/", "/page/", "/vulnerability-disclosure-policy", "/disclosed-vulnerabilities"]
# Date formats in posts: "Mar 3, 2026" / "March 3, 2026"
DATE_RE = re.compile(r"\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},\s+\d{4}\b", re.IGNORECASE)


def _is_post_href(href: str) -> bool:
    if not href.startswith("/"):
        return False
    stripped = href.strip("/")
    if "/" in stripped or not stripped:
        return False
    for prefix in SKIP_PREFIXES:
        if href.startswith(prefix):
            return False
    return "#" not in href and "?" not in href


def _get_advisory_urls() -> list[str]:
    seen: set[str] = set()
    urls = []
    page = 1
    while True:
        page_url = URL if page == 1 else f"{URL}/page/{page}/"
        try:
            resp = requests.get(page_url, headers=HEADERS, timeout=30)
            if resp.status_code == 404:
                break
            resp.raise_for_status()
        except requests.RequestException:
            break
        soup = BeautifulSoup(resp.text, "html.parser")
        new_found = False
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if href.startswith(URL):
                href = href[len(URL):]
            if _is_post_href(href):
                full_url = URL + href.rstrip("/")
                if full_url not in seen:
                    seen.add(full_url)
                    urls.append(full_url)
                    new_found = True
        if not new_found:
            break
        page += 1
        time.sleep(0.1)
    return urls


def _vendor_from_title(title: str) -> list[str]:
    """Extract vendor/product from post title.
    Common patterns: 'Product Name CVE-...' or 'Title (Product Name CVE-...)'.
    """
    # Pattern: "(...CVE-XXXX-XXXXX...)" - get content before CVE in parens
    m = re.search(r"\(([^)]+CVE-\d{4}-\d+[^)]*)\)", title, re.IGNORECASE)
    if m:
        inner = m.group(1)
        # Remove CVE part, keep product
        product = re.sub(r"CVE-\d{4}-\d+", "", inner, flags=re.IGNORECASE).strip(" -,")
        if product and len(product) > 2:
            return [product]
    # Pattern: known vendor names before CVE mention
    m2 = re.search(r"^(.+?)\s+CVE-\d{4}-\d+", title, re.IGNORECASE)
    if m2:
        product = m2.group(1).strip()
        # Strip common prefixes
        product = re.sub(r"^(CVE-\d{4}-\d+\s*[&-]?\s*)+", "", product, flags=re.IGNORECASE).strip()
        if product and len(product) > 2 and len(product) < 80:
            return [product]
    return []


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
    if not cves:
        return None

    # Date: look for "Mar 3, 2026" near top
    date_str = None
    for line in lines[:20]:
        m = DATE_RE.search(line)
        if m:
            s = m.group(0)
            for fmt in ("%b %d, %Y", "%B %d, %Y"):
                try:
                    dt = datetime.strptime(s, fmt)
                    date_str = dt.strftime("%y/%m/%d")
                    break
                except ValueError:
                    pass
            if date_str:
                break

    # Researcher: "By  —\n<Name>\n—" pattern
    researcher = []
    for i, line in enumerate(lines[:30]):
        if line in ("By  —", "By —", "By—") and i + 1 < len(lines):
            name = lines[i + 1].strip(" —")
            if name and len(name) < 60:
                researcher = [name]
            break
        # Alternative: line starts with "By " followed by name
        m2 = re.match(r"^By\s+[—–]\s*(.+)", line)
        if m2:
            name = m2.group(1).strip(" —–")
            if name and len(name) < 60:
                researcher = [name]
            break

    # Vendor from h1 / first heading
    vendor = []
    h1 = soup.find("h1")
    if h1:
        title = h1.get_text(strip=True)
        vendor = _vendor_from_title(title)

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
