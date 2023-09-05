import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin

# URL base
base_url = "https://www.trustwave.com/"

# URL de la página
url = "https://www.trustwave.com/en-us/resources/security-resources/security-advisories/"

# Realiza la solicitud GET a la URL
response = requests.get(url)

# Verifica si la solicitud fue exitosa (código de respuesta 200)
if response.status_code == 200:
    # Analiza el contenido HTML de la página
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Encuentra todos los enlaces cuyo texto sea "Read"
    read_links = soup.find_all('a', text='Read')
    
    # Lista para almacenar los CVEs únicos encontrados
    unique_cves = set()
    
    # Bucle para procesar cada enlace "Read"
    for link in read_links:
        # Convierte la URL relativa a absoluta
        link_url = urljoin(base_url, link['href'])
        
        # Realiza una solicitud GET al enlace absoluto
        link_response = requests.get(link_url)
        
        if link_response.status_code == 200:
            # Analiza el contenido HTML de la página del enlace
            link_soup = BeautifulSoup(link_response.text, 'html.parser')
            
            # Busca y extrae los CVEs usando una expresión regular
            cve_pattern = r'CVE-\d{4}-\d{4,5}'
            cves = re.findall(cve_pattern, link_soup.get_text())
            
            # Agrega los CVEs únicos a la lista
            unique_cves.update(cves)
    
    # Calcula la longitud total de los CVEs únicos encontrados
    total_length = len(unique_cves)
    
    # Imprime la longitud total
    print("Longitud total de CVEs únicos encontrados:", total_length)

else:
    print("Error al realizar la solicitud:", response.status_code)