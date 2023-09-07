import aiohttp
import asyncio
from bs4 import BeautifulSoup
import re  # Importar el módulo de expresiones regulares
from urllib.parse import urljoin  # Importar la función urljoin para convertir enlaces relativos en absolutos

# Función para obtener los enlaces que cumplen con el patrón usando regex
async def get_links(url, session):
    async with session.get(url, ssl=False) as response:
        if response.status == 200:
            print(f"Procesando: {url}")
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            
            # Expresión regular para buscar enlaces que cumplan con el patrón
            link_pattern = re.compile(r'/ww-en/analytics/threatscape/pt-.*')
            
            # Encontrar enlaces que coincidan con el patrón
            links = [a['href'] for a in soup.find_all('a', href=link_pattern)]
            
            return links
        else:
            print(f"No se pudo obtener la página {url}. Código de estado:", response.status)
            return []

# Función para buscar CVEs en la respuesta de los enlaces
async def find_cves(links, session):
    cve_pattern = r"CVE-\d{4}-\d{4,5}"  # Expresión regular para buscar CVEs
    
    total_cves = set()  # Conjunto para almacenar los CVEs
    
    for link in links:
        # Convertir el enlace relativo en un enlace absoluto
        absolute_link = urljoin("https://www.ptsecurity.com/", link)
        
        async with session.get(absolute_link, ssl=False) as response:
            if response.status == 200:
                print(f"Procesando enlace: {absolute_link}")
                html = await response.text()
                
                # Buscar CVEs en la respuesta
                cves = re.findall(cve_pattern, html)
                total_cves.update(cves)
                
                # Imprimir los CVEs encontrados en este enlace
                print("\nCVEs encontrados en", absolute_link, ":")
                for cve in cves:
                    print(cve)
            else:
                print(f"No se pudo obtener la página {absolute_link}. Código de estado:", response.status)
    
    return total_cves

async def main():
    # Crear una sesión de aiohttp
    async with aiohttp.ClientSession() as session:
        total_cves = set()  # Conjunto para almacenar todos los CVEs
        
        # Iterar a través de las páginas del 1 al 58
        for page in range(1, 59):
            base_url = f"https://www.ptsecurity.com/ww-en/ajax/get.threats.php?severity=all&yearPeriod=all&yearIntervalFrom=2008&monthIntervalFrom=1&yearIntervalTo=2030&monthIntervalTo=12&vendor_name=&software_name=&pageSize=10&PAGEN_1={page}"
            
            # Obtener los enlaces que cumplen con el patrón en la página actual
            links = await get_links(base_url, session)
            
            # Buscar CVEs en la respuesta de los enlaces de la página actual
            cves = await find_cves(links, session)
            
            # Agregar los CVEs encontrados en esta página al conjunto total
            total_cves.update(cves)
        
        # Imprimir la lista de CVEs únicos encontrados en todas las páginas
        print("\nCVEs únicos encontrados:")
        for cve in total_cves:
            print(cve)
        
        # Imprimir la cantidad total numérica de CVEs únicos encontrados
        print(f"\nCantidad total de CVEs únicos encontrados: {len(total_cves)}")

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())