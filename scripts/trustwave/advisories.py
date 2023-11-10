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
    read_links = soup.find_all('a', string='Read')
    
    # Calcula la longitud total de los CVEs únicos encontrados
    total_advisories = len(read_links)
    
    # Imprime la longitud total
    print("Total de advisories:", total_advisories)

else:
    print("Error al realizar la solicitud:", response.status_code)