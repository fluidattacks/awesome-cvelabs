import requests
from bs4 import BeautifulSoup
import re

# URL del sitio web inicial
initial_url = 'https://www.sentinelone.com/labs/'

# Realizar una solicitud GET a la página web inicial
response = requests.get(initial_url)

# Verificar si la solicitud fue exitosa
if response.status_code == 200:
    # Analizar el contenido HTML de la página web inicial
    soup = BeautifulSoup(response.text, 'html.parser')

    # Buscar enlaces que comiencen con "https://www.sentinelone.com/labs/"
    lab_links = [link.get('href') for link in soup.find_all('a', href=True) if link.get('href').startswith('https://www.sentinelone.com/labs/')]

    # Inicializar una lista para almacenar los enlaces únicos de autores
    author_links_unique = set()

    # Recorrer los enlaces de laboratorios y buscar enlaces de autores en cada uno
    for lab_link in lab_links:
        lab_response = requests.get(lab_link)
        if lab_response.status_code == 200:
            lab_soup = BeautifulSoup(lab_response.text, 'html.parser')
            
            # Buscar enlaces que comiencen con "https://www.sentinelone.com/blog/author/"
            author_links = [link.get('href') for link in lab_soup.find_all('a', href=True) if link.get('href').startswith('https://www.sentinelone.com/blog/author/')]

            # Agregar los enlaces de autores encontrados a la lista de enlaces únicos
            author_links_unique.update(author_links)

    # Imprimir los enlaces únicos de autores y la cantidad total
    print("Enlaces únicos de autores encontrados:")
    for author_link in author_links_unique:
        print(author_link)
    
    print(f"\nCantidad total de enlaces únicos de autores: {len(author_links_unique)}")
else:
    print('Error al obtener la página inicial:', response.status_code)