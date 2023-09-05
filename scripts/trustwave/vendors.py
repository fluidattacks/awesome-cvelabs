import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

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
    
    # Lista para almacenar los vendors únicos encontrados
    unique_vendors = set()
    
    # Bucle para procesar cada enlace "Read"
    for link in read_links:
        # Convierte la URL relativa a absoluta
        link_url = urljoin(base_url, link['href'])
        
        # Realiza una solicitud GET al enlace absoluto
        link_response = requests.get(link_url)
        
        if link_response.status_code == 200:
            # Analiza el contenido HTML de la página del enlace
            link_soup = BeautifulSoup(link_response.text, 'html.parser')
            
            # Busca el vendor en el texto de la página
            vendor_pattern = r'Vendor:\s+(.*?)\s+\('
            vendors = re.findall(vendor_pattern, link_soup.get_text())
            
            # Agrega los vendors únicos a la lista
            unique_vendors.update(vendors)
    
    # Calcula la cantidad de vendors únicos capturados en total
    total_vendors = len(unique_vendors)
    
    # Imprime la cantidad total de vendors únicos
    print("Cantidad total de vendors únicos capturados:", total_vendors)
    
    # Imprime cada uno de los vendors únicos
    print("Vendors únicos capturados:")
    for vendor in unique_vendors:
        print(vendor)

else:
    print("Error al realizar la solicitud:", response.status_code)