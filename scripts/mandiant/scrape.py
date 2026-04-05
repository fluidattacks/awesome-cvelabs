#!/usr/bin/env python3
"""Mandiant Vulnerability Disclosures scraper — Playwright edition.
Source: GitHub API to list repo contents, then raw markdown for CVEs/researchers/vendors.
"""
import asyncio, re, sys
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import async_playwright

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Mandiant"
URL = "https://github.com/mandiant/Vulnerability-Disclosures"
REPO = "mandiant/Vulnerability-Disclosures"
API_BASE = f"https://api.github.com/repos/{REPO}/contents"
GH_BASE = f"https://github.com/{REPO}"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/master"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)
DATE_RE = re.compile(r"(?:Date|Published|Disclosed)[:\s]+(\w+ \d{1,2},?\s*\d{4}|\d{4}-\d{2}-\d{2})", re.IGNORECASE)


def _raw_url_from_gh(url: str) -> str | None:
    if "/blob/" in url:
        return url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/")
    if "/tree/" in url:
        path = url.split("/tree/master/", 1)[-1]
        name = path.rstrip("/").split("/")[-1]
        return f"{RAW_BASE}/{path}/{name}.md"
    return None


async def _list_dir(api, path: str = "") -> list:
    url = API_BASE + (f"/{path}" if path else "")
    try:
        resp = await api.get(url, headers={"Accept": "application/vnd.github.v3+json"})
        return await resp.json()
    except Exception:
        return []


async def _parse_raw(api, raw_url: str, gh_url: str) -> Advisory | None:
    try:
        resp = await api.get(raw_url)
        if resp.status != 200:
            return Advisory(url=gh_url)
        content = await resp.text()
    except Exception:
        return Advisory(url=gh_url)

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(content)))

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

    researchers = []
    disc_m = re.search(r"##\s*Discovery\s+Credits\n(.*?)(?=\n##|\Z)", content, re.IGNORECASE | re.DOTALL)
    if disc_m:
        lines = re.findall(r"[-*]\s*(.+)", disc_m.group(1))
        for line in lines:
            name = line.split(",")[0].lstrip("- ").strip()
            if name:
                researchers.append(name)

    vendors = []
    vendor_m = re.search(r"(?:Vendor|Affected\s+Vendor)[:\s]+([^\n,\.]{2,40})", content, re.IGNORECASE)
    if vendor_m:
        v = vendor_m.group(1).strip()
        if v:
            vendors = [v]

    return Advisory(url=gh_url, date=date_str, cve_ids=cves, researchers=researchers, vendors=vendors)


async def _collect_advisory_urls(api) -> list[tuple[str, str]]:
    entries = []
    seen: set[str] = set()
    root = await _list_dir(api)

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
        year_entries = await _list_dir(api, year)
        for item in year_entries:
            name = item["name"]
            if item["type"] == "dir":
                url = f"{GH_BASE}/tree/master/{year}/{name}"
            else:
                url = f"{GH_BASE}/blob/master/{year}/{name}"
            if url not in seen:
                seen.add(url)
                entries.append((name, url))

    return entries


async def scrape() -> list[Advisory]:
    advisories = []
    async with async_playwright() as p:
        api = await p.request.new_context()
        entries = await _collect_advisory_urls(api)
        for name, gh_url in entries:
            raw_url = _raw_url_from_gh(gh_url)
            if raw_url:
                adv = await _parse_raw(api, raw_url, gh_url)
            else:
                adv = Advisory(url=gh_url)
            if adv:
                advisories.append(adv)
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
