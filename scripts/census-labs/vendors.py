import aiohttp
import asyncio
from bs4 import BeautifulSoup

async def fetch_page(session, url):
    async with session.get(url) as response:
        return await response.text()

async def parse_vendors(page_content, vendor_set):
    soup = BeautifulSoup(page_content, 'html.parser')
    vendor_elements = soup.find_all('tr')

    for element in vendor_elements:
        td_elements = element.find_all('td')
        if len(td_elements) == 2 and td_elements[0].text.strip() == 'Affected Products:':
            product_text = td_elements[1].text.strip()
            # Extraer el nombre del vendedor de la descripción del producto
            vendor_name = product_text.split()[0]
            vendor_set.add(vendor_name)

async def main():
    base_url = "https://census-labs.com/news/category/advisories/?page="
    total_vendor_set = set()

    async with aiohttp.ClientSession() as session:
        tasks = []

        for page_num in range(1, 9):
            url = base_url + str(page_num)
            page_content = await fetch_page(session, url)
            task = asyncio.ensure_future(parse_vendors(page_content, total_vendor_set))
            tasks.append(task)

        await asyncio.gather(*tasks)

    print(f"Total de vendedores únicos encontrados: {len(total_vendor_set)}")

if __name__ == "__main__":
    asyncio.run(main())