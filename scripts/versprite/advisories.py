import requests
from bs4 import BeautifulSoup
import re

# Función para obtener enlaces que comienzan con la URL dada
def obtener_enlaces(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    enlaces_tags = soup.find_all('a', href=re.compile(r'^https://versprite.com/advisories/'))
    enlaces = [enlace.get('href').strip() for enlace in enlaces_tags]
    return enlaces

# URL de la página principal
url_base = 'https://versprite.com/advisories/'

# Conjunto para almacenar enlaces únicos
enlaces_unicos = set()

# Primero, procesamos la página 1 sin número de página
page_num = 1
url = url_base
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

# Obtener enlaces de la página 1
enlaces = obtener_enlaces(url)
enlaces_unicos.update(enlaces)

# Luego, loop a través de las páginas del 2 al 4
for page_num in range(2, 5):
    url = f'{url_base}page/{page_num}/'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Obtener enlaces de la página actual
    enlaces = obtener_enlaces(url)
    enlaces_unicos.update(enlaces)

# Imprimir la cantidad total de enlaces únicos encontrados
cantidad_total_enlaces_unicos = len(enlaces_unicos)
print(f'Cantidad total de enlaces únicos encontrados: {cantidad_total_enlaces_unicos}')
