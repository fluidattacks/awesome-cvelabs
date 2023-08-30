import requests
from bs4 import BeautifulSoup

# Función para obtener el texto de enlaces PDF con rel="bookmark"
def get_pdf_links_text(page_url):
    response = requests.get(page_url)
    pdf_texts = []

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        # Encontrar enlaces con rel="bookmark" que tengan una extensión .pdf
        pdf_links = soup.find_all('a', rel='bookmark', href=lambda href: href and href.endswith('.pdf'))
        # Extraer y agregar el texto de los enlaces a la lista
        pdf_texts.extend(pdf_link.text.strip() for pdf_link in pdf_links)

    return pdf_texts

# Recorrer las páginas del 1 al 8
for page_number in range(1, 9):
    if page_number == 1:
        page_url = "https://ioactive.com/resources/disclosures/"
    else:
        page_url = f"https://ioactive.com/resources/disclosures/page/{page_number}/"
    
    pdf_texts = get_pdf_links_text(page_url)

    if pdf_texts:
        for pdf_text in pdf_texts:
            print(pdf_text)