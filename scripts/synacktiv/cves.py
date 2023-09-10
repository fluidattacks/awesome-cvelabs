import requests
from bs4 import BeautifulSoup
import re

# URL de la página que quieres analizar
url = "https://www.synacktiv.com/en/advisories"

# Realizamos una solicitud GET a la URL
response = requests.get(url)

# Verificamos que la solicitud haya sido exitosa
if response.status_code == 200:
    # Parseamos el contenido HTML de la página
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Buscamos todas las cadenas que coincidan con el patrón CVE-xxxx-xxxx o CVE-xxxx-xxxxx
    cve_pattern = r'CVE-\d{4}-\d{4,5}'
    cve_matches = re.findall(cve_pattern, response.text)
    
    # Eliminamos duplicados usando un conjunto (set)
    unique_cves = set(cve_matches)
    
    # Imprimimos la lista de CVEs únicos
    print("CVEs encontrados:")
    for cve in unique_cves:
        print(cve)
    
    # Imprimimos el número total de CVEs únicos encontrados
    print(f"Total de CVEs únicos encontrados: {len(unique_cves)}")
else:
    print(f"No se pudo acceder a la URL. Código de estado: {response.status_code}")