import requests
from bs4 import BeautifulSoup
import re

# URL de la página 9
url = 'https://www.nozominetworks.com/vulnerability-advisories?page=9'

# Realizar la solicitud HTTP
response = requests.get(url)

# Verificar si la solicitud fue exitosa
if response.status_code == 200:
    # Analizar el contenido HTML de la página
    soup = BeautifulSoup(response.text, 'html.parser')

    # Encontrar todos los elementos <h2>
    h2_elements = soup.find_all('h2')

    # Inicializar un conjunto para almacenar todos los CVEs únicos
    all_cve_unique = set()

    # Buscar CVEs dentro de los elementos <h2>
    cve_pattern = r'CVE-\d{4}-\d{4,5}'
    for h2 in h2_elements:
        text = h2.get_text()
        cve_matches = re.findall(cve_pattern, text)
        all_cve_unique.update(cve_matches)

    # Contar la cantidad total de CVEs únicos
    total_unique_cve = len(all_cve_unique)

    # Imprimir los CVEs únicos y el total
    print("CVEs únicos encontrados:")
    for cve in all_cve_unique:
        print(cve)
    print(f"Total de CVEs únicos: {total_unique_cve}")
else:
    print(f"Error al hacer la solicitud HTTP. Código de estado: {response.status_code}")