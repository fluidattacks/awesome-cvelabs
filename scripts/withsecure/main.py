import asyncio
import aiohttp
import re
from bs4 import BeautifulSoup

async def fetch_json(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()

async def fetch_html(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.text()

async def get_advisories_and_cves(url):
    data = await fetch_json(url)

    advisories = data.get('items', [])
    total_advisories = sum(1 for advisory in advisories if 'description' in advisory)

    unique_cves = set()

    for advisory in advisories:
        page_url = advisory.get('pageUrl', '')
        if page_url.endswith('.json'):
            cves = await get_cves_from_json(page_url)
        else:
            cves = await get_cves_from_html(page_url)
        unique_cves.update(cves)

    return total_advisories, unique_cves

async def get_cves_from_json(url):
    data = await fetch_json(url)
    page_content = data.get('items', [])[0].get('description', '')

    cve_pattern = r"CVE-\d{4}-\d{4,5}"
    cve_matches = set(re.findall(cve_pattern, page_content))

    return cve_matches

async def get_cves_from_html(url):
    html_content = await fetch_html(url)

    # Utiliza BeautifulSoup para analizar el HTML
    soup = BeautifulSoup(html_content, 'html.parser')

    # Encuentra todas las coincidencias de patrones CVE en el contenido
    cve_pattern = r"CVE-\d{4}-\d{4,5}"
    cve_matches = set(re.findall(cve_pattern, str(soup)))

    return cve_matches

async def main():
    url = "https://labs.withsecure.com/advisories/_jcr_content/root/responsivegrid/responsivegrid/responsivegrid/customcontainer_copy/custom-container/customcontainer/custom-container/pagefilter.model.json?k=1700171153779"

    total_advisories, unique_cves = await get_advisories_and_cves(url)

    print(f"Total de Advisories encontrados: {total_advisories}")
    print(f"Total de CVEs únicos encontrados: {len(unique_cves)}")

if __name__ == "__main__":
    asyncio.run(main())
