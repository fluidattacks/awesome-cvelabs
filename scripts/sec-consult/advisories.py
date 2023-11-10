import asyncio
import aiohttp
import re

async def fetch_url(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            html = await response.text()
    return html

async def main():
    years = range(2003, 2024)

    for year in years:
        base_url = f"https://sec-consult.com/vulnerability-lab/{year}/"
        year_html = await fetch_url(base_url)
        advisory_links = re.findall(r'href="/vulnerability-lab/advisory/([^"]+)"', year_html)

    total_advisory_links = len(advisory_links)
    print(f"Total de advisories: {total_advisory_links}")

if __name__ == "__main__":
    asyncio.run(main())
