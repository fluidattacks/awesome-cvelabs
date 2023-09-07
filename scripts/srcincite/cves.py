import aiohttp
import asyncio
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin

MAX_RETRIES = 3
CONCURRENT_REQUESTS = 100  # Aumentar el número de solicitudes concurrentes

async def fetch_url(session, url, retries=MAX_RETRIES):
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            return await response.text()
    except aiohttp.ClientError as e:
        if retries > 0:
            print(f"Error al conectar con {url}. Intentando nuevamente ({MAX_RETRIES - retries + 1}/{MAX_RETRIES})...")
            return await fetch_url(session, url, retries - 1)
        else:
            print(f"No se pudo conectar con {url} después de varios intentos. Error: {e}")
            return None

async def get_links_with_keywords(session, url):
    html_content = await fetch_url(session, url)
    if html_content is None:
        return []

    print(f"Obteniendo enlaces desde {url}...")
    soup = BeautifulSoup(html_content, 'html.parser')
    links = soup.find_all('a', href=True)
    keyword_links = []

    for link in links:
        if re.search(r'\[ZDI\]|\[SRC\]', link.text):
            href = link['href']
            # Convertir enlaces relativos a absolutos
            if not href.startswith(('http://', 'https://')):
                parsed_url = urlparse(url)
                href = urljoin(url, href)
            keyword_links.append(href)

    return keyword_links

async def find_cves_on_page(session, url):
    html_content = await fetch_url(session, url)
    if html_content is None:
        return set()

    print(f"Buscando CVEs en {url}...")
    cves = set()
    text = html_content
    cve_matches = re.findall(r'CVE-\d{4}-\d{4,5}', text)
    cves.update(cve_matches)
    return cves

async def main():
    initial_url = "https://srcincite.io/advisories/"
    async with aiohttp.ClientSession() as session:
        initial_links = await get_links_with_keywords(session, initial_url)
        
        # Utiliza asyncio.gather para manejar las solicitudes concurrentes
        tasks = [find_cves_on_page(session, link) for link in initial_links]
        results = await asyncio.gather(*tasks)
        
        unique_cves = set()
        for cves in results:
            unique_cves.update(cves)

        total_unique_cves = len(unique_cves)
        print(f"La cantidad total de CVEs únicos encontrados es: {total_unique_cves}")

if __name__ == "__main__":
    asyncio.run(main())