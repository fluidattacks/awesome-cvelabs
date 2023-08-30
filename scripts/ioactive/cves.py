import requests
from bs4 import BeautifulSoup
import fitz  # PyMuPDF
import re

# Función para obtener los enlaces PDF con rel="bookmark"
def get_pdf_links(page_url):
    response = requests.get(page_url)
    pdf_links = []

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        # Encontrar enlaces con rel="bookmark" que tengan una extensión .pdf
        pdf_links = soup.find_all('a', rel='bookmark', href=lambda href: href and href.endswith('.pdf'))

    return pdf_links

# Función para buscar y contar los CVEs en un archivo PDF
def count_cves_in_pdf(pdf_url):
    try:
        response = requests.get(pdf_url)
        if response.status_code == 200:
            pdf_data = response.content
            pdf_document = fitz.open(stream=pdf_data, filetype="pdf")
            cve_pattern = r'\bCVE-\d{4}-\d{4,5}\b'  # Patrón para buscar CVEs
            cves_found = set()

            for page_number in range(pdf_document.page_count):
                page = pdf_document.load_page(page_number)
                text = page.get_text()

                # Buscar CVEs en el texto de la página
                cves = re.findall(cve_pattern, text)
                cves_found.update(cves)

            pdf_document.close()
            return cves_found
    except Exception as e:
        print(f"Error al procesar el archivo PDF: {e}")
        return set()

# Conjunto para almacenar los CVEs únicos
unique_cves = set()

# Recorrer las páginas del 1 al 8
for page_number in range(1, 9):
    if page_number == 1:
        page_url = "https://ioactive.com/resources/disclosures/"
    else:
        page_url = f"https://ioactive.com/resources/disclosures/page/{page_number}/"
    
    pdf_links = get_pdf_links(page_url)

    if pdf_links:
        print(f"Buscando CVEs en la página {page_number}:")

        for pdf_link in pdf_links:
            pdf_url = pdf_link.get('href')

            # Si la URL es relativa, conviértela en absoluta
            if not pdf_url.startswith('http'):
                pdf_url = f"https://ioactive.com{pdf_url}"

            cves_found = count_cves_in_pdf(pdf_url)

            if cves_found:
                print(f"En el PDF {pdf_url}:")
                for cve in cves_found:
                    print(cve)
                unique_cves.update(cves_found)

# Imprimir el número total de CVEs únicos encontrados
print(f"\nNúmero total de CVEs únicos encontrados: {len(unique_cves)}")
