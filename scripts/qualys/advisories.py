import aiohttp
import asyncio
from bs4 import BeautifulSoup

async def fetch_url(url, retry_count=3):
    async with aiohttp.ClientSession() as session:
        for retry in range(retry_count):
            try:
                async with session.get(url) as response:
                    return await response.content.read()
            except aiohttp.ClientError as e:
                print(f"Error al conectar a {url}. Intento {retry+1}/{retry_count}")
                if retry == retry_count - 1:
                    print(f"No se pudo conectar a {url} después de {retry_count} intentos.")
                    return b""

async def main():
    url = "https://www.qualys.com/research/security-advisories/"
    
    content = await fetch_url(url)
    soup = BeautifulSoup(content, "html.parser")

    advisory_links = soup.find_all("p", class_="advisory__link")
    print("Total de advisories: ", len(advisory_links))

if __name__ == "__main__":
    asyncio.run(main())
