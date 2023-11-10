import requests
from bs4 import BeautifulSoup

# URL de la página inicial
url_inicial = "https://labs.integrity.pt/advisories/"

# Realizar una solicitud GET a la página inicial
response = requests.get(url_inicial)

# Comprobar si la solicitud fue exitosa
if response.status_code == 200:
    soup = BeautifulSoup(response.text, 'html.parser')
    advisories = set()  # Usamos un conjunto para evitar duplicados

    # Buscar todos los enlaces que comiencen con '/advisories/'
    for link in soup.find_all('a', href=True):
        if link['href'].startswith('/advisories/'):
            advisories.add(link['href'])

    # Calcular la cantidad numérica total de advisories
    total_advisories = len(advisories)
    print(f"Total de advisories encontrados: {total_advisories}")

else:
    print(f"No se pudo acceder a la página {url_inicial}")
