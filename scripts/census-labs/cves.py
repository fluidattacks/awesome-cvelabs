import aiohttp
import asyncio
from bs4 import BeautifulSoup
import re

async def fetch_page(session, url):
    async with session.get(url) as response:
        return await response.text()

async def parse_cves(page_content, cve_set):
    soup = BeautifulSoup(page_content, 'html.parser')
    cve_elements = soup.find_all(text=lambda text: 'CVE' in text)
    
    for element in cve_elements:
        # Usamos una expresión regular para encontrar los CVE válidos
        cve_matches = re.findall(r'CVE-\d{4}-\d{4,5}', element)
        
        for cve in cve_matches:
            cve_set.add(cve)

async def main():
    base_url = "https://census-labs.com/news/category/advisories/?page="
    total_cve_set = set()

    async with aiohttp.ClientSession() as session:
        tasks = []

        for page_num in range(1, 9):
            url = base_url + str(page_num)
            page_content = await fetch_page(session, url)
            task = asyncio.ensure_future(parse_cves(page_content, total_cve_set))
            tasks.append(task)

        await asyncio.gather(*tasks)

    print(f"Total de CVEs únicos encontrados: {len(total_cve_set)}")

if __name__ == "__main__":
    asyncio.run(main())