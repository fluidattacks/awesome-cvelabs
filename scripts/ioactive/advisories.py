import requests
from bs4 import BeautifulSoup
import re

# Conjunto para almacenar los advisories únicos
unique_advisories = set()

# Recorrer las páginas del 1 al 8
for page_number in range(1, 9):
    if page_number == 1:
        page_url = "https://ioactive.com/resources/disclosures/"
    else:
        page_url = f"https://ioactive.com/resources/disclosures/page/{page_number}/"

    response = requests.get(page_url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        pdf_links = soup.find_all('a', rel='bookmark', href=lambda href: href and href.endswith('.pdf'))

        if pdf_links:

            for pdf_link in pdf_links:
                pdf_url = pdf_link.get('href')

                # Si la URL es relativa, conviértela en absoluta
                if not pdf_url.startswith('http'):
                    pdf_url = f"https://ioactive.com{pdf_url}"

                unique_advisories.add(pdf_url)

# Imprimir el número total de advisories únicos encontrados
print(f"\nNúmero total de advisories únicos encontrados: {len(unique_advisories)}")
