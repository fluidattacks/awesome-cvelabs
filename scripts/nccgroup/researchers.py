import requests
from bs4 import BeautifulSoup

# URL de la página a la que quieres acceder
url = 'https://research.nccgroup.com/category/technical-advisories/'

# Enlace base para buscar
base_link = 'https://research.nccgroup.com/author/'

# Realizar la solicitud GET a la página
response = requests.get(url)

if response.status_code == 200:
    # Analizar el contenido de la página con BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # Encontrar todos los enlaces que comienzan con el enlace base
    researcher_links = [link.get('href') for link in soup.find_all('a', href=True) if link.get('href').startswith(base_link)]

    # Eliminar duplicados manteniendo el orden original
    unique_researchers = list(dict.fromkeys(researcher_links))

    # Imprimir los nombres de los investigadores únicos
    for researcher_link in unique_researchers:
        print(researcher_link)

    # Imprimir la longitud de unique_researchers
    print(f'Número de investigadores únicos: {len(unique_researchers)}')

else:
    print(f'Error al acceder a la página. Código de estado: {response.status_code}')