import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

# URL base y número de páginas a recorrer
base_url = "https://www.coresecurity.com/core-labs/advisories?page="
num_pages = 11  # Esto incluye las páginas desde 0 hasta 10

# Patrón de búsqueda para CVEs
cve_pattern = re.compile(r"CVE-\d{4}-\d{4,5}")

# Conjunto para almacenar CVEs únicos
unique_cves = set()

# User-Agent personalizado
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0"
}

async def fetch_advisory(session, url):
    async with session.get(url, headers=headers) as response:
        if response.status == 200:
            advisory_html = await response.text()
            advisory_soup = BeautifulSoup(advisory_html, "html.parser")
            cves = cve_pattern.findall(advisory_soup.get_text())
            unique_cves.update(cves)
        else:
            print(f"No se pudo acceder a la página {url}")

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = []

        for page_number in range(num_pages):
            url = f"{base_url}{page_number}"
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")
                    advisory_links = soup.find_all(href=re.compile(r"/core-labs/advisories/"))
                    for link in advisory_links:
                        advisory_url = link["href"]
                        advisory_url = urljoin(url, advisory_url)
                        tasks.append(fetch_advisory(session, advisory_url))

        await asyncio.gather(*tasks)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

    # Imprimir la cantidad total de CVEs únicos encontrados
    print(f"Total de CVEs únicos encontrados: {len(unique_cves)}")