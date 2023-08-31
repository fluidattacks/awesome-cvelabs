import aiohttp
import asyncio
from bs4 import BeautifulSoup

base_url = "https://www.fortiguard.com/zeroday?type=vuln&page="
unique_vendors = set()

async def fetch_and_parse(page_number):
    url = base_url + str(page_number)
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                title_divs = soup.find_all('div', class_='title')
                for div in title_divs:
                    vendor = div.find_all('a')[1].text.strip()
                    unique_vendors.add(vendor)

async def main():
    # Crear una lista de tareas asíncronas
    tasks = [fetch_and_parse(page_number) for page_number in range(1, 47)]

    # Ejecutar tareas asíncronas
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())

    print("Vendors únicos encontrados:")
    for vendor in unique_vendors:
        print(vendor)

    print(f"Total de vendors únicos encontrados: {len(unique_vendors)}")
