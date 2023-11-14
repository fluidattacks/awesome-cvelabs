import requests
from bs4 import BeautifulSoup

# URL de la página 9
url = 'https://www.nozominetworks.com/vulnerability-advisories?page=9'

# Realizar la solicitud HTTP
response = requests.get(url)

# Verificar si la solicitud fue exitosa
if response.status_code == 200:
    # Analizar el contenido HTML de la página
    soup = BeautifulSoup(response.text, 'html.parser')

    # Encontrar todos los elementos <a> que contienen el texto "Details"
    details_links = soup.find_all('a', string='Details')

    # Contar la cantidad total de advisories
    total_advisories = len(details_links)

    print(f"Total de advisories: {total_advisories}")
else:
    print(f"Error al hacer la solicitud HTTP. Código de estado: {response.status_code}")
