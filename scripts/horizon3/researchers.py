import asyncio
import requests
from bs4 import BeautifulSoup

base_url = "https://www.horizon3.ai/red-team-blog/page/"
total_pages = 3
author_links = set()

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

        links = soup.find_all('a', attrs={'rel': 'author'})

        print(f"Encontrados {len(links)} enlaces en página {page_number}")

        for link in links:
            author = link.text.strip()
            author_links.add(author)
            print(f"Autor encontrado: {author}")
    except Exception as e:
        print(f"Error al procesar la página {page_number}: {str(e)}")

async def main():
    print("Iniciando la extracción de datos...")
    for page_number in range(1, total_pages + 1):
        await scrape_page(page_number)

    print(f"Extracción de datos completada.")
    print(f"Se encontraron {len(author_links)} autores únicos:")
    print(", ".join(author_links))

if __name__ == "__main__":
    asyncio.run(main())