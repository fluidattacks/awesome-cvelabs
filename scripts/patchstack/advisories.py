from bs4 import BeautifulSoup
import asyncio
import aiohttp
import re

async def fetch_url(session, url):
    async with session.get(url) as response:
        if response.status == 200:
            return await response.text()

async def process_article(session, article_url, total_articles):
    article_html = await fetch_url(session, article_url)
    if article_html:
        total_articles.append(1)

async def main():
    base_url = "https://patchstack.com/category/security-advisories/"
    total_articles = []  # Lista para almacenar el contador de artículos
    async with aiohttp.ClientSession() as session:
        main_html = await fetch_url(session, base_url)
        if main_html:
            soup = BeautifulSoup(main_html, "html.parser")
            article_links = soup.find_all("a", href=re.compile(r"^https://patchstack.com/articles/"))

            tasks = [process_article(session, article_link["href"], total_articles) for article_link in article_links]
            await asyncio.gather(*tasks)

    print(f"Total de advisories: {len(total_articles)}")

if __name__ == "__main__":
    asyncio.run(main())
