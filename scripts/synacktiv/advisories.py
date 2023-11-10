import requests
from bs4 import BeautifulSoup

# URL de la página que quieres analizar
url = "https://www.synacktiv.com/en/advisories"

# Realizamos una solicitud GET a la URL
response = requests.get(url)

# Verificamos que la solicitud haya sido exitosa
if response.status_code == 200:
    # Parseamos el contenido HTML de la página
    soup = BeautifulSoup(response.text, 'html.parser')

    # Buscamos todos los elementos <div class="view-content">
    view_content_divs = soup.find_all('div', class_='view-content')

    # Inicializamos el contador total de <div class="views-row">
    total_views_rows = 0

    # Iteramos sobre cada <div class="view-content">
    for view_content_div in view_content_divs:
        # Buscamos todos los <div class="views-row"> dentro de cada <div class="view-content">
        views_row_divs = view_content_div.find_all('div', class_='views-row')

        # Incrementamos el contador total
        total_views_rows += len(views_row_divs)

    # Imprimimos el número total de <div class="views-row"> encontrados
    print(f"Total de <div class=\"views-row\"> encontrados: {total_views_rows}")

else:
    print(f"No se pudo acceder a la URL. Código de estado: {response.status_code}")
