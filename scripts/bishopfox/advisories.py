import requests
from bs4 import BeautifulSoup
import re

base_url = "https://bishopfox.com/blog/advisories?page="

def extract_links_from_page(url):
    response = requests.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        target_div = soup.find("div", class_="relative grid gap-10 gap-y-14 grid-cols-1 sm:grid-cols-2 md:grid-cols-3 pb-14")
        
        if target_div:
            links = target_div.find_all("a", href=True)
            filtered_links = [link["href"] for link in links if link["href"].startswith("https://bishopfox.com/blog/")]
            return filtered_links
        else:
            return []
    else:
        return []

# Obtener enlaces de todas las páginas del 1 al 6
all_links = []

for page_number in range(1, 7):
    url = f"{base_url}{page_number}"
    all_links.extend(extract_links_from_page(url))
        
print(f"Total de advisories: {len(all_links)}")