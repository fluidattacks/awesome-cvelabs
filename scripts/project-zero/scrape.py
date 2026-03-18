#!/usr/bin/env python3
"""Google Project Zero scraper. Outputs data.json.
Source: Monorail Issues API → issue detail pages → date, CVE IDs, researchers, vendors.
"""
import re, sys, time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parents[2]))
from lab_model import CVELab, Advisory

LAB = "Google Project Zero"
URL = "https://bugs.chromium.org/p/project-zero/issues"
ISSUES_URL = "https://bugs.chromium.org/prpc/monorail.Issues/ListIssues"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; awesome-cvelabs-scraper/1.0)",
    "Accept": "application/json",
}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,5}", re.IGNORECASE)


def _get_issue_urls() -> list[str]:
    payload = {
        "projectName": "project-zero",
        "query": "Disclosed=Yes",
        "canValue": 1,
        "pagination": {"maxItems": 1000, "start": 0},
    }
    seen: set[str] = set()
    urls = []

    try:
        resp = requests.post(ISSUES_URL, json=payload, headers=HEADERS, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            for issue in data.get("issues", []):
                iid = issue.get("localId") or issue.get("issueId")
                if iid:
                    url = f"{URL}/detail?id={iid}"
                    if url not in seen:
                        seen.add(url)
                        urls.append(url)
    except Exception as e:
        print(f"  API error: {e}")

    # Fallback: static HTML list
    if not urls:
        try:
            resp2 = requests.get(f"{URL}/list?can=1&q=&sort=-id&num=1000", headers=HEADERS, timeout=30)
            resp2.raise_for_status()
            ids = re.findall(r"detail\?id=(\d+)", resp2.text)
            for iid in ids:
                url = f"{URL}/detail?id={iid}"
                if url not in seen:
                    seen.add(url)
                    urls.append(url)
        except Exception as e:
            print(f"  Fallback error: {e}")

    urls.sort(key=lambda u: int(re.search(r"id=(\d+)", u).group(1)) if re.search(r"id=(\d+)", u) else 0, reverse=True)
    return urls


def _parse_issue(url: str) -> Advisory | None:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code != 200:
            return Advisory(url=url)
    except requests.RequestException:
        return Advisory(url=url)

    soup = BeautifulSoup(resp.text, "html.parser")
    text = soup.get_text(" ")

    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(text)))

    # Date
    date_str = None
    m = re.search(r"(\d{4}-\d{2}-\d{2})", text)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%Y-%m-%d")
            date_str = dt.strftime("%y/%m/%d")
        except ValueError:
            pass

    return Advisory(url=url, date=date_str, cve_ids=cves)


def scrape() -> list[Advisory]:
    issue_urls = _get_issue_urls()

    # If we can't reach the API, fall back to urls.lst
    if not issue_urls:
        urls_lst = Path(__file__).parent / "urls.lst"
        if urls_lst.exists():
            with open(urls_lst) as f:
                issue_urls = [l.strip() for l in f if l.strip()]
            print(f"  Loaded {len(issue_urls)} URLs from urls.lst")

    advisories = []
    for url in issue_urls[:200]:  # Limit to avoid excessive requests
        adv = _parse_issue(url)
        if adv:
            advisories.append(adv)
        time.sleep(0.15)

    # For remaining URLs beyond limit, add URL-only entries
    for url in issue_urls[200:]:
        advisories.append(Advisory(url=url))

    return advisories


if __name__ == "__main__":
    advisories = scrape()
    lab = CVELab(lab=LAB, url=URL,
                 scraped_at=datetime.now(timezone.utc),
                 advisories=advisories)
    out = Path(__file__).parent / "data.yaml"
    out.write_text(lab.to_yaml())
    print(f"{LAB}: A={lab.A} Q={lab.Q} V={lab.V} R={lab.R} → {out}")
