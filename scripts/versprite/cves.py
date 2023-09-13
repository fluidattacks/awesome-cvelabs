import requests
from bs4 import BeautifulSoup
import re

# Función para obtener CVEs de una página de advisory
def obtener_cves(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    cve_tags = soup.find_all(text=re.compile(r'CVE-\d{4}-\d{4,5}'))
    cves = [cve.strip() for cve in cve_tags]
    return cves

# URL de la página principal
url_base = 'https://versprite.com/advisories/'

# Conjunto para almacenar CVEs únicos
cves_unicos = set()

# Primero, procesamos la página 1 sin número de página
page_num = 1
url = url_base
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

# Obtener CVEs de la página 1
cves = obtener_cves(url)
cves_unicos.update(cves)

# Luego, loop a través de las páginas del 2 al 4
for page_num in range(2, 5):
    url = f'{url_base}page/{page_num}/'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Obtener CVEs de la página actual
    cves = obtener_cves(url)
    cves_unicos.update(cves)

# Imprimir la cantidad total de CVEs únicos encontrados
cantidad_total_cves_unicos = len(cves_unicos)
print(f'Cantidad total de CVEs únicos encontrados: {cantidad_total_cves_unicos}')