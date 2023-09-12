import asyncio
import requests
from bs4 import BeautifulSoup
import re

base_url = "https://www.horizon3.ai/red-team-blog/page/"
total_pages = 3
cve_pattern = r'CVE-\d{4}-\d{4,5}'
cves = set()

user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0"

async def scrape_page(page_number):
    try:
        url = f"{base_url}{page_number}"
        headers = {"User-Agent": user_agent}
        
        print(f"Solicitando página {page_number}...")
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        print(f"Recibida respuesta de página {page_number}")

        soup = BeautifulSoup(response.text, 'html.parser')

        content = soup.get_text()

        cve_matches = re.findall(cve_pattern, content)

        print(f"Encontradas {len(cve_matches)} CVE en página {page_number}")

        for cve in cve_matches:
            cves.add(cve)
            print(f"CVE encontrada: {cve}")
    except Exception as e:
        print(f"Error al procesar la página {page_number}: {str(e)}")

async def main():
    print("Iniciando la extracción de CVE...")
    for page_number in range(1, total_pages + 1):
        await scrape_page(page_number)

    print(f"Extracción de CVE completada.")
    print(f"Se encontraron {len(cves)} CVE únicas:")
    print(", ".join(cves))

if __name__ == "__main__":
    asyncio.run(main())