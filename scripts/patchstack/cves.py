import asyncio
import aiohttp
import re
from bs4 import BeautifulSoup

async def fetch_url(session, url):
    async with session.get(url) as response:
        if response.status == 200:
            return await response.text()

async def find_cves_in_article(session, article_url, unique_cves):
    article_html = await fetch_url(session, article_url)
    if article_html:
        cve_pattern = r"CVE-\d{4}-\d{4,5}"
        cve_matches = re.findall(cve_pattern, article_html)

        if cve_matches:
            unique_cves.update(cve_matches)

async def main():
    base_url = "https://patchstack.com/category/security-advisories/"
    unique_cves = set()
    async with aiohttp.ClientSession() as session:
        main_html = await fetch_url(session, base_url)
        if main_html:
            soup = BeautifulSoup(main_html, "html.parser")
            article_links = soup.find_all("a", href=re.compile(r"^https://patchstack.com/articles/"))

            tasks = [find_cves_in_article(session, article_link["href"], unique_cves) for article_link in article_links]
            await asyncio.gather(*tasks)

    print(f"Total de CVEs únicos encontrados: {len(unique_cves)}")

if __name__ == "__main__":
    asyncio.run(main())