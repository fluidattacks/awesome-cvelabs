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

async def get_vendors_from_page(session, url):
    html_content = await fetch_url(session, url)
    if html_content is None:
        return []

    print(f"Obteniendo vendedores desde {url}...")
    soup = BeautifulSoup(html_content, 'html.parser')
    vendors = []

    # Buscar la tabla con los vendedores
    table = soup.find('table')
    if table:
        rows = table.find_all('tr')
        for row in rows:
            cols = row.find_all('td')
            if len(cols) == 2 and cols[0].text.strip() == "AFFECTED VENDORS":
                vendor_links = cols[1].find_all('a')
                vendor_names = [link.text.strip() for link in vendor_links]
                vendors.extend(vendor_names)

    return vendors

async def main():
    initial_url = "https://srcincite.io/advisories/"
    async with aiohttp.ClientSession() as session:
        initial_links = await get_links_with_keywords(session, initial_url)
        unique_vendors = set()

        # Utiliza asyncio.gather para manejar las solicitudes concurrentes
        tasks = [get_vendors_from_page(session, link) for link in initial_links]
        results = await asyncio.gather(*tasks)

        for vendors in results:
            unique_vendors.update(vendors)

        print("Vendedores afectados encontrados:")
        for vendor in unique_vendors:
            print(vendor)
        
        print(f"La cantidad total de vendedores únicos encontrados es: {len(unique_vendors)}")

if __name__ == "__main__":
    asyncio.run(main())
