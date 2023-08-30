import requests
from bs4 import BeautifulSoup
import html

# URL base
base_url = "https://ioactive.com/resources/disclosures/"

# Conjunto para almacenar los nombres de los investigadores únicos
unique_researchers = set()

# Realizar la solicitud a la página principal (página 1)
response = requests.get(base_url)
if response.status_code == 200:
    soup = BeautifulSoup(response.text, 'html.parser')
    researchers_divs = soup.find_all('div', class_='authors__names')

    for div in researchers_divs:
        # Decodificar entidades HTML como "&amp;" a "&" y eliminar espacios adicionales
        researcher_names = html.unescape(div.text.strip()).split('&')  
        for name in researcher_names:
            name = name.strip().replace("  ", " ")  # Eliminar espacios iniciales y finales y espacios adicionales
            if name:
                unique_researchers.add(name)

# Realizar solicitudes de paginación desde la página 2 a la 8
for page_number in range(2, 9):
    page_url = f"{base_url}page/{page_number}/"
    response = requests.get(page_url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        researchers_divs = soup.find_all('div', class_='authors__names')

        for div in researchers_divs:
            # Decodificar entidades HTML como "&amp;" a "&" y eliminar espacios adicionales
            researcher_names = html.unescape(div.text.strip()).split('&')
            for name in researcher_names:
                name = name.strip().replace("  ", " ")  # Eliminar espacios iniciales y finales y espacios adicionales
                if name:
                    unique_researchers.add(name)

# Imprimir los investigadores únicos alineados a la izquierda sin líneas en blanco
print("Investigadores únicos encontrados:")
for researcher in unique_researchers:
    print(researcher)

print(f"\nCantidad total de investigadores únicos: {len(unique_researchers)}")