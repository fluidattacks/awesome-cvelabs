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

async def main():
    initial_url = "https://srcincite.io/advisories/"
    async with aiohttp.ClientSession() as session:
        advisory_links = await get_links_with_keywords(session, initial_url)

        total_advisories = len(advisory_links)
        print(f"Total de advisories: {total_advisories}")

if __name__ == "__main__":
    asyncio.run(main())
