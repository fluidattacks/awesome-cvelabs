import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

# URL de la página inicial
url_inicial = "https://labs.integrity.pt/advisories/"

# Realizar una solicitud GET a la página inicial
response = requests.get(url_inicial)

# Comprobar si la solicitud fue exitosa
if response.status_code == 200:
    soup = BeautifulSoup(response.text, 'html.parser')
    advisories = set()  # Usamos un conjunto para evitar duplicados
    researchers_encontrados = set()  # Conjunto para almacenar los nombres de los investigadores únicos

    # Buscar todos los enlaces que comiencen con '/advisories/'
    for link in soup.find_all('a', href=True):
        if link['href'].startswith('/advisories/'):
            advisories.add(link['href'])

    # Convertir las URLs relativas en URLs absolutas
    base_url = url_inicial if url_inicial.endswith('/') else url_inicial + '/'
    absolute_advisories = [urljoin(base_url, advisory) for advisory in advisories]

    # Expresión regular para buscar los investigadores entre "Discovery by" y " <"
    researcher_pattern = re.compile(r"Discovery by ([^<]+) <")

    # Recorrer las URLs absolutas para obtener los investigadores
    for absolute_url in absolute_advisories:
        advisory_response = requests.get(absolute_url)
        if advisory_response.status_code == 200:
            advisory_soup = BeautifulSoup(advisory_response.text, 'html.parser')
            credits_element = advisory_soup.find('strong', text="Credits:")
            if credits_element:
                researchers_text = credits_element.find_next_sibling(text=True).strip()
                researchers_match = researcher_pattern.search(researchers_text)
                if researchers_match:
                    researcher_name = researchers_match.group(1).strip()
                    researchers_encontrados.add(researcher_name)

    # Mostrar los investigadores encontrados
    if researchers_encontrados:
        print("Investigadores encontrados:")
        for researcher in researchers_encontrados:
            print(researcher)
        
        # Calcular la cantidad numérica total de investigadores únicos
        total_researchers = len(researchers_encontrados)
        print(f"Total de investigadores únicos encontrados: {total_researchers}")
    else:
        print("No se encontraron investigadores en la página.")

else:
    print(f"No se pudo acceder a la página {url_inicial}")
