import asyncio
import aiohttp
import re
from urllib.parse import urljoin

async def fetch_url(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            html = await response.text()
    return html

async def get_cves_from_page(url):
    html = await fetch_url(url)
    cve_pattern = r"CVE-\d{4}-\d{4,5}"
    cve_matches = re.findall(cve_pattern, html)
    return cve_matches

async def main():
    years = range(2003, 2024)
    unique_cves = set()

    for year in years:
        base_url = f"https://sec-consult.com/vulnerability-lab/{year}/"
        year_html = await fetch_url(base_url)
        advisory_links = re.findall(r'href="/vulnerability-lab/advisory/([^"]+)"', year_html)

        for advisory_link in advisory_links:
            advisory_url = urljoin(base_url, f"/vulnerability-lab/advisory/{advisory_link}")
            cves = await get_cves_from_page(advisory_url)
            unique_cves.update(cves)

    total_unique_cves = len(unique_cves)
    print(f"Total de CVEs únicos encontrados: {total_unique_cves}")

if __name__ == "__main__":
    asyncio.run(main())