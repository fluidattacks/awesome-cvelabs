import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

# URL base y número de páginas a recorrer
base_url = "https://www.coresecurity.com/core-labs/advisories?page="
num_pages = 11  # Esto incluye las páginas desde 0 hasta 10

# Advisory links
advisory_links = []

# User-Agent personalizado
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0"
}

async def main():
    async with aiohttp.ClientSession() as session:

        for page_number in range(num_pages):
            url = f"{base_url}{page_number}"
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")
                    # Extiende la lista con los enlaces encontrados en la página actual
                    advisory_links.extend(soup.find_all(href=re.compile(r"/core-labs/advisories/")))
        
        print("Total advisories: ", len(advisory_links))

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
