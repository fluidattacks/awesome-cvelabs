import aiohttp
import asyncio
from bs4 import BeautifulSoup
import re

async def fetch_url(url, retry_count=3):
    async with aiohttp.ClientSession() as session:
        for retry in range(retry_count):
            try:
                async with session.get(url) as response:
                    return await response.content.read()
            except aiohttp.ClientError as e:
                print(f"Error al conectar a {url}. Intento {retry+1}/{retry_count}")
                if retry == retry_count - 1:
                    print(f"No se pudo conectar a {url} después de {retry_count} intentos.")
                    return b""

async def main():
    url = "https://www.qualys.com/research/security-advisories/"
    
    print("Iniciando solicitud a:", url)
    content = await fetch_url(url)
    print("Solicitud completada.")

    soup = BeautifulSoup(content, "html.parser")

    advisory_links = soup.find_all("p", class_="advisory__link")

    unique_cves = set()

    print("Extrayendo enlaces y buscando CVEs...")

    tasks = []
    for p in advisory_links:
        link = p.find("a", class_="q-link")
        if link:
            advisory_url = link["href"]
            task = asyncio.create_task(fetch_url(advisory_url))
            tasks.append((advisory_url, task))

    for advisory_url, task in tasks:
        advisory_content = await task
        advisory_content_str = advisory_content.decode(errors="ignore")
        cve_matches = re.findall(r"CVE-\d{4}-\d{4,5}", advisory_content_str)
        unique_cves.update(cve_matches)
        print(f"Procesado: {advisory_url}")

    print("CVEs únicos encontrados:")
    for cve in unique_cves:
        print(cve)

    print("Total de CVEs únicos:", len(unique_cves))

if __name__ == "__main__":
    asyncio.run(main())