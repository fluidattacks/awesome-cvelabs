import requests
from bs4 import BeautifulSoup

# URL de la página a la que quieres acceder
url = 'https://research.nccgroup.com/category/technical-advisories/'

# Realizar la solicitud GET a la página
response = requests.get(url)

if response.status_code == 200:
    # Analizar el contenido de la página con BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # Encontrar todos los enlaces con texto "Read more"
    read_more_links = soup.find_all('a', string="Read more")

    # Imprimir el número total de advisories
    print(f'Número total de advisories: {len(read_more_links)}')

else:
    print(f'Error al acceder a la página. Código de estado: {response.status_code}')
