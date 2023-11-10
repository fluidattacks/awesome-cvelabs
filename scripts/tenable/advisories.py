import requests
from bs4 import BeautifulSoup
import re

# Realizar la solicitud HTTP a la URL
url = "https://www.tenable.com/security/research"
response = requests.get(url)

# Comprobar si la solicitud fue exitosa
if response.status_code == 200:
    # Analizar el contenido HTML de la página
    soup = BeautifulSoup(response.text, 'html.parser')

    # Encontrar todos los enlaces que comiencen con "/security/research"
    href_pattern = re.compile(r'^/security/research')
    research_links = soup.find_all('a', href=href_pattern)

    # Imprimir la cantidad de enlaces encontrados
    print(f"Total de advisories:  {len(research_links)}")
else:
    print("Error al realizar la solicitud HTTP.")
