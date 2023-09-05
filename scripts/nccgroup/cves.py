import requests
from bs4 import BeautifulSoup
import re

# URL de la página a la que quieres acceder
url = 'https://research.nccgroup.com/category/technical-advisories/'

# Realizar la solicitud GET a la página
response = requests.get(url)

if response.status_code == 200:
    # Analizar el contenido de la página con BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # Encontrar todos los enlaces con texto "Read more"
    read_more_links = [link.get('href') for link in soup.find_all('a', text="Read more")]

    # Inicializar una lista para almacenar los CVEs encontrados
    cves = []

    # Iterar sobre los enlaces "Read more" para buscar CVEs
    for link in read_more_links:
        page_response = requests.get(link)
        if page_response.status_code == 200:
            page_soup = BeautifulSoup(page_response.text, 'html.parser')
            
            # Buscar coincidencias de CVEs en el contenido de la página
            cve_matches = re.findall(r'CVE-\d{4}-\d{4,5}', page_soup.get_text())

            # Agregar los CVEs encontrados a la lista
            cves.extend(cve_matches)

    # Eliminar duplicados manteniendo el orden original
    unique_cves = list(dict.fromkeys(cves))

    # Imprimir los CVEs únicos
    for cve in unique_cves:
        print(cve)

    # Imprimir la longitud numérica total de CVEs únicos
    print(f'Número total de CVEs únicos: {len(unique_cves)}')

else:
    print(f'Error al acceder a la página. Código de estado: {response.status_code}')