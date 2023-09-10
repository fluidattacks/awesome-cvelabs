import requests
from bs4 import BeautifulSoup
import re

# Realizar la solicitud HTTP a la URL
url = "https://www.tenable.com/security/research"
response = requests.get(url)

# Comprobar si la solicitud fue exitosa
if response.status_code == 200:
    # Analizar el contenido HTML de la página
    soup = BeautifulSoup(response.text, 'html.parser')

    # Encontrar todos los textos que coincidan con el patrón CVE-xxxx-xxxx o CVE-xxxx-xxxxx
    cve_pattern = r'CVE-\d{4}-\d{4,5}'
    cve_matches = re.findall(cve_pattern, soup.get_text())

    # Eliminar duplicados utilizando un conjunto (set)
    unique_cves = set(cve_matches)

    # Imprimir la cantidad de CVEs únicos encontrados
    print(f"Se encontraron {len(unique_cves)} CVEs únicos en total.")
else:
    print("Error al realizar la solicitud HTTP.")