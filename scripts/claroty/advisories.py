import requests
from bs4 import BeautifulSoup
import re

# Función para obtener el número total de coincidencias del texto "See Details" en una página
def get_advisories(url):
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()

        # Utilizamos una expresión regular para buscar el texto "See Details" en el texto
        advisories = re.findall(r'See Details', text)

        return advisories
    else:
        return []

# URL base
base_url = "https://claroty.com/team82/disclosure-dashboard?page="

# Lista para almacenar el número total de coincidencias de "See Details"
total_advisories = 0

# Iteramos a través de las páginas del 1 al 21
for page_number in range(1, 22):
    url = f"{base_url}{page_number}"
    advisories_pagina = get_advisories(url)
    total_advisories += len(advisories_pagina)

# Imprimimos el número total de coincidencias de "See Details"
print("Número total de advisories encontrados:", total_advisories)
