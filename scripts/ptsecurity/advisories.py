import aiohttp
import asyncio
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin

async def get_links(url, session):
    async with session.get(url, ssl=False) as response:
        if response.status == 200:
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')

            link_pattern = re.compile(r'/ww-en/analytics/threatscape/pt-.*')
            links = [a['href'] for a in soup.find_all('a', href=link_pattern)]

            return links
        else:
            print(f"No se pudo obtener la página {url}. Código de estado:", response.status)
            return []

async def main():
    async with aiohttp.ClientSession() as session:
        total_advisories = 0
        for page in range(1, 59):
            base_url = f"https://www.ptsecurity.com/ww-en/ajax/get.threats.php?severity=all&yearPeriod=all&yearIntervalFrom=2008&monthIntervalFrom=1&yearIntervalTo=2030&monthIntervalTo=12&vendor_name=&software_name=&pageSize=10&PAGEN_1={page}"
            links = await get_links(base_url, session)
            total_advisories += len(links)
        
        print(f"Total de advisories: {total_advisories}")

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
