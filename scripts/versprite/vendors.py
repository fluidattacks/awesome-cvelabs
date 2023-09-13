import requests
from bs4 import BeautifulSoup

# Función para obtener el vendor de una página de advisory
def obtener_vendor(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    vendor_tag = soup.find('h4', text='Vendor')
    if vendor_tag:
        vendor = vendor_tag.find_next('p').text.strip()
        return vendor
    else:
        return None

# URL de la página principal
url_base = 'https://versprite.com/advisories/'

# Conjunto para almacenar vendors únicos
vendors_unicos = set()

# Primero, procesamos la página 1 sin número de página
page_num = 1
url = url_base
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

# Buscar enlaces que empiezan con 'https://versprite.com/advisories/'
enlaces = [a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('https://versprite.com/advisories/')]

# Procesar los enlaces y obtener los vendors
for enlace in enlaces:
    vendor = obtener_vendor(enlace)
    if vendor:
        vendors_unicos.add(vendor)

# Luego, loop a través de las páginas del 2 al 4
for page_num in range(2, 5):
    url = f'{url_base}page/{page_num}/'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Buscar enlaces que empiezan con 'https://versprite.com/advisories/'
    enlaces = [a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('https://versprite.com/advisories/')]
    
    # Procesar los enlaces y obtener los vendors
    for enlace in enlaces:
        vendor = obtener_vendor(enlace)
        if vendor:
            vendors_unicos.add(vendor)

# Imprimir la cantidad total de vendors únicos
cantidad_total_vendors_unicos = len(vendors_unicos)
print(f'Cantidad total de vendors únicos encontrados: {cantidad_total_vendors_unicos}')