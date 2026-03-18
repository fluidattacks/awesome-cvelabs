#!/usr/bin/env python3
"""Mandiant Vulnerability Disclosures scraper. Outputs data.json.
Source: GitHub API to list repo contents, then raw markdown for CVEs/researchers/vendors.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Mandiant"
URL = "https://github.com/mandiant/Vulnerability-Disclosures"
REPO = "mandiant/Vulnerability-Disclosures"
API_BASE = f"https://api.github.com/repos/{REPO}/contents"
GH_BASE = f"https://github.com/{REPO}"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/master"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)",
    "Accept": "application/vnd.github.v3+json",
}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
DATE_RE = re.compile(r"(?:Date|Published|Disclosed)[:\s]+(\w+ \d{1,2},?\s*\d{4}|\d{4}-\d{2}-\d{2})", re.IGNORECASE)


def _list_dir(path: str = "") -> list:
    url = API_BASE + (f"/{path}" if path else "")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return []


def _raw_url_from_gh(url: str) -> str | None:
    if "/blob/" in url:
        return url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/")
    if "/tree/" in url:
        path = url.split("/tree/master/", 1)[-1]
        name = path.rstrip("/").split("/")[-1]
        return f"{RAW_BASE}/{path}/{name}.md"
    return None


def _parse_raw(raw_url: str, gh_url: str) -> Advisory | None:
    try:
        resp = requests.get(raw_url, headers=HEADERS, timeout=30)
        if resp.status_code != 200:
            return Advisory(url=gh_url)
        content = resp.text
    except Exception:
        return Advisory(url=gh_url)

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(content)))

    # Date
    date_str = None
    dm = DATE_RE.search(content)
    if dm:
        s = dm.group(1).strip()
        for fmt in ("%B %d, %Y", "%B %d %Y", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s.replace(",", ""), fmt.replace(",", ""))
                date_str = dt.strftime("%y/%m/%d")
                break
            except ValueError:
                pass

    # Researchers from "## Discovery Credits"
    researchers = []
    disc_m = re.search(r"##\s*Discovery\s+Credits\n(.*?)(?=\n##|\Z)", content, re.IGNORECASE | re.DOTALL)
    if disc_m:
        lines = re.findall(r"[-*]\s*(.+)", disc_m.group(1))
        for line in lines:
            name = line.split(",")[0].lstrip("- ").strip()
            if name:
                researchers.append(name)

    # Vendors from "## Affected Products" or "Vendor:"
    vendors = []
    vendor_m = re.search(r"(?:Vendor|Affected\s+Vendor)[:\s]+([^\n,\.]{2,40})", content, re.IGNORECASE)
    if vendor_m:
        v = vendor_m.group(1).strip()
        if v:
            vendors = [v]

    return Advisory(url=gh_url, date=date_str, cve_ids=cves, researchers=researchers, vendors=vendors)


def _collect_advisory_urls() -> list[tuple[str, str]]:
    """Returns list of (name, github_url) for each advisory."""
    entries = []
    seen: set[str] = set()
    root = _list_dir()

    year_dirs = []
    for item in root:
        name = item["name"]
        typ = item["type"]
        if typ == "dir" and name.isdigit() and len(name) == 4:
            year_dirs.append(name)
        elif typ == "dir" and (name.startswith("FEYE-") or name.startswith("MNDT-")):
            url = f"{GH_BASE}/tree/master/{name}"
            if url not in seen:
                seen.add(url)
                entries.append((name, url))
        elif typ == "file" and name.endswith(".md") and (name.startswith("FEYE-") or name.startswith("MNDT-")):
            url = f"{GH_BASE}/blob/master/{name}"
            if url not in seen:
                seen.add(url)
                entries.append((name, url))

    for year in sorted(year_dirs):
        year_entries = _list_dir(year)
        for item in year_entries:
            name = item["name"]
            if item["type"] == "dir":
                url = f"{GH_BASE}/tree/master/{year}/{name}"
            else:
                url = f"{GH_BASE}/blob/master/{year}/{name}"
            if url not in seen:
                seen.add(url)
                entries.append((name, url))
        time.sleep(0.05)

    return entries


def scrape() -> list[Advisory]:
    entries = _collect_advisory_urls()
    advisories = []

    for name, gh_url in entries:
        raw_url = _raw_url_from_gh(gh_url)
        if raw_url:
            adv = _parse_raw(raw_url, gh_url)
        else:
            adv = Advisory(url=gh_url)
        if adv:
            advisories.append(adv)
        time.sleep(0.1)

    return advisories


if __name__ == "__main__":
    advisories = scrape()
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
