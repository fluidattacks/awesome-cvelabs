import requests
from bs4 import BeautifulSoup

# URL del sitio web
url = 'https://www.sentinelone.com/labs/our-cves/'

# Realizar una solicitud GET a la página web
response = requests.get(url)

# Verificar si la solicitud fue exitosa
if response.status_code == 200:
    # Obtener el contenido de la página web
    page_content = response.text

    # Utilizar BeautifulSoup para facilitar el análisis HTML
    soup = BeautifulSoup(page_content, 'html.parser')

    # Encontrar todos los enlaces que contienen un div con texto "Link"
    advisory_links = [a['href'] for a in soup.find_all('a') if a.find('div', string='Link')]

    print("Total Advisories: ", len(advisory_links))
else:
    print('Error al obtener la página:', response.status_code)
