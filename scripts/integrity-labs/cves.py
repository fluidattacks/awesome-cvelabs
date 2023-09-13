import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

# URL de la página inicial
url_inicial = "https://labs.integrity.pt/advisories/"

# Realizar una solicitud GET a la página inicial
response = requests.get(url_inicial)

# Comprobar si la solicitud fue exitosa
if response.status_code == 200:
    soup = BeautifulSoup(response.text, 'html.parser')
    advisories = set()  # Usamos un conjunto para evitar duplicados
    cves_encontrados = set()  # Conjunto para almacenar los CVEs únicos encontrados

    # Buscar todos los enlaces que comiencen con '/advisories/'
    for link in soup.find_all('a', href=True):
        if link['href'].startswith('/advisories/'):
            advisories.add(link['href'])

    # Convertir las URLs relativas en URLs absolutas
    base_url = url_inicial if url_inicial.endswith('/') else url_inicial + '/'
    absolute_advisories = [urljoin(base_url, advisory) for advisory in advisories]

    # Recorrer las URLs absolutas para obtener los CVEs
    for absolute_url in absolute_advisories:
        advisory_response = requests.get(absolute_url)
        if advisory_response.status_code == 200:
            advisory_soup = BeautifulSoup(advisory_response.text, 'html.parser')
            cves = re.findall(r'\bCVE-\d{4}-\d{4,5}\b', advisory_soup.get_text())
            if cves:
                print(f"CVEs en {absolute_url}:")
                for cve in cves:
                    print(cve)
                    cves_encontrados.add(cve)

    # Calcular la cantidad numérica total de CVEs únicos
    total_cves = len(cves_encontrados)
    print(f"Total de CVEs únicos encontrados: {total_cves}")

else:
    print(f"No se pudo acceder a la página {url_inicial}")