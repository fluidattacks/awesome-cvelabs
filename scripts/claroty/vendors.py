import requests
from bs4 import BeautifulSoup

# Función para obtener los vendors de una página
def get_vendors(url):
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        # Buscamos los elementos <td> con la clase CSS adecuada
        vendor_cells = soup.find_all('td', class_='p-2 md:p-4 sm-max:flex gap-2')
        
        vendors = set()
        for cell in vendor_cells:
            # Buscamos el texto del primer elemento <span> en el <td>
            vendor_span = cell.find('span', class_='w-1/3 shrink-0 text-subtle md:hidden', text='Vendor')
            if vendor_span:
                vendor_text = cell.get_text(strip=True).replace('Vendor', '')
                vendors.add(vendor_text)
                print(vendor_text)

        return vendors
    return set()

# URL base
base_url = "https://claroty.com/team82/disclosure-dashboard?page="

# Conjunto para almacenar los vendors únicos
vendors_unicos = set()

# Iteramos a través de las páginas del 1 al 21
for page_number in range(1, 22):
    url = f"{base_url}{page_number}"
    vendors_pagina = get_vendors(url)
    vendors_unicos.update(vendors_pagina)

# Calculamos la longitud total numérica de todos los vendors encontrados
total_vendor_length = len(vendors_unicos)

# Imprimimos la longitud total numérica de todos los vendors
print("Longitud total numérica de todos los vendors encontrados:", total_vendor_length)