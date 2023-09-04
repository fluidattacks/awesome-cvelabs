import requests
from bs4 import BeautifulSoup
import re

base_url = "https://bishopfox.com/blog/advisories?page="
cve_pattern = r"CVE-\d{4}-\d{4,5}"

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

def extract_cves_from_url(url):
    response = requests.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text()
        cves_found = set(re.findall(cve_pattern, text))
        return cves_found
    else:
        return set()

# Obtener enlaces de todas las páginas del 1 al 6
all_links = []

for page_number in range(1, 7):
    url = f"{base_url}{page_number}"
    all_links.extend(extract_links_from_page(url))

if all_links:
    print("Enlaces de interés encontrados:")
    for link in all_links:
        print(link)
    
    print("Buscando CVEs en los enlaces de interés:")
    
    unique_cves = set()
    
    for link in all_links:
        cves = extract_cves_from_url(link)
        if cves:
            unique_cves.update(cves)
    
    if unique_cves:
        print("CVEs encontrados:")
        for cve in unique_cves:
            print(cve)
        
        print(f"Total de CVEs únicos encontrados: {len(unique_cves)}")  # Muestra la cantidad total
    else:
        print("No se encontraron CVEs en los enlaces de interés.")
else:
    print("No se encontraron enlaces de interés.")