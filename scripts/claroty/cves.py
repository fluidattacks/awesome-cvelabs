import requests
from bs4 import BeautifulSoup
import re

# Función para obtener los CVE únicos de una página
def get_cves(url):
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()

        # Utilizamos una expresión regular para buscar CVEs en el texto
        cves = set(re.findall(r'CVE-\d{4}-\d{4,5}', text))

        return cves
    else:
        return set()

# URL base
base_url = "https://claroty.com/team82/disclosure-dashboard?page="

# Lista para almacenar los CVEs únicos
cves_unicos = set()

# Iteramos a través de las páginas del 1 al 21
for page_number in range(1, 22):
    url = f"{base_url}{page_number}"
    cves_pagina = get_cves(url)
    cves_unicos.update(cves_pagina)

# Imprimimos la cantidad total de CVEs únicos encontrados
print("Cantidad total de CVEs únicos encontrados:", len(cves_unicos))