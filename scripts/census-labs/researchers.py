import aiohttp
import asyncio
from bs4 import BeautifulSoup

async def fetch_page(session, url):
    async with session.get(url) as response:
        return await response.text()

async def parse_researchers(page_content, researcher_set):
    soup = BeautifulSoup(page_content, 'html.parser')
    researcher_elements = soup.find_all('tr')

    for element in researcher_elements:
        td_elements = element.find_all('td')
        if len(td_elements) == 2 and td_elements[0].text.strip() == 'Discovered by:':
            researcher_name = td_elements[1].text.strip()
            researcher_set.add(researcher_name)

async def main():
    base_url = "https://census-labs.com/news/category/advisories/?page="
    total_researcher_set = set()

    async with aiohttp.ClientSession() as session:
        tasks = []

        for page_num in range(1, 9):
            url = base_url + str(page_num)
            page_content = await fetch_page(session, url)
            task = asyncio.ensure_future(parse_researchers(page_content, total_researcher_set))
            tasks.append(task)

        await asyncio.gather(*tasks)

    print(f"Total de investigadores únicos encontrados: {len(total_researcher_set)}")

if __name__ == "__main__":
    asyncio.run(main())