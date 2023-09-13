import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# URL de la página inicial
url_inicial = "https://labs.integrity.pt/advisories/"

# Realizar una solicitud GET a la página inicial
response = requests.get(url_inicial)

# Comprobar si la solicitud fue exitosa
if response.status_code == 200:
    soup = BeautifulSoup(response.text, 'html.parser')
    advisories = set()  # Usamos un conjunto para evitar duplicados
    vendors_encontrados = set()  # Conjunto para almacenar los nombres de los vendedores únicos

    # Buscar todos los enlaces que comiencen con '/advisories/'
    for link in soup.find_all('a', href=True):
        if link['href'].startswith('/advisories/'):
            advisories.add(link['href'])

    # Convertir las URLs relativas en URLs absolutas
    base_url = url_inicial if url_inicial.endswith('/') else url_inicial + '/'
    absolute_advisories = [urljoin(base_url, advisory) for advisory in advisories]

    # Recorrer las URLs absolutas para obtener los nombres de los vendedores
    for absolute_url in absolute_advisories:
        advisory_response = requests.get(absolute_url)
        if advisory_response.status_code == 200:
            advisory_soup = BeautifulSoup(advisory_response.text, 'html.parser')
            vendor_text = advisory_soup.find('strong', text="Vendor:")
            if vendor_text:
                vendor_text = vendor_text.find_next_sibling(text=True).strip()
                vendors_encontrados.add(vendor_text)

    # Mostrar los nombres de los vendedores encontrados
    if vendors_encontrados:
        print("Vendedores encontrados:")
        for vendor in vendors_encontrados:
            print(vendor)
        
        # Calcular la cantidad numérica total de vendedores únicos
        total_vendors = len(vendors_encontrados)
        print(f"Total de vendedores únicos encontrados: {total_vendors}")
    else:
        print("No se encontraron nombres de vendedores en la página.")

else:
    print(f"No se pudo acceder a la página {url_inicial}")
