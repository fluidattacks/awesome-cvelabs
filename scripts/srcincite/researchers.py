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

async def get_researchers_from_page(session, url):
    html_content = await fetch_url(session, url)
    if html_content is None:
        return []

    print(f"Obteniendo investigadores desde {url}...")
    soup = BeautifulSoup(html_content, 'html.parser')
    researchers = []

    # Buscar la tabla con los investigadores
    table = soup.find('table')
    if table:
        rows = table.find_all('tr')
        for row in rows:
            cols = row.find_all('td')
            if len(cols) == 2 and cols[0].text.strip() == "CREDIT":
                researcher_text = cols[1].text.strip()
                # Dividir el texto en investigadores usando "and", "&" o ","
                researcher_names = re.split(r' and | & |, ', researcher_text)
                for name in researcher_names:
                    # Eliminar paréntesis y todo lo que haya después
                    cleaned_name = re.sub(r'\(.+?\)', '', name).strip()
                    # Verificar si el nombre no contiene "of" y no es un equipo
                    if cleaned_name.endswith((" of Incite Team", " of Source Incite", "")):
                        # Eliminar el "of..."
                        cleaned_name = re.sub(r' of .+', '', cleaned_name)
                        researchers.append(cleaned_name)

    return researchers

async def main():
    initial_url = "https://srcincite.io/advisories/"
    async with aiohttp.ClientSession() as session:
        initial_links = await get_links_with_keywords(session, initial_url)
        researchers_set = set()

        # Utiliza asyncio.gather con 100 solicitudes concurrentes.
        tasks = [get_researchers_from_page(session, link) for link in initial_links]
        results = await asyncio.gather(*tasks)

        for researchers in results:
            researchers_set.update(researchers)

        # Eliminar duplicados y agrupar "mr_me" bajo "Steven Seeley"
        unique_researchers = set()
        for researcher in researchers_set:
            if researcher == "mr_me" or researcher.startswith("Incite Team:"):
                unique_researchers.add("Steven Seeley")
            else:
                unique_researchers.add(researcher.strip())

        print("Investigadores encontrados:")
        for researcher in unique_researchers:
            print(researcher)

        print(f"La cantidad total de investigadores únicos encontrados es: {len(unique_researchers)}")

if __name__ == "__main__":
    asyncio.run(main())