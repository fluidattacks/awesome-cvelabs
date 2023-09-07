import aiohttp
import asyncio
from bs4 import BeautifulSoup

# URL base de la página web con variable de página
base_url = "https://www.ptsecurity.com/ww-en/ajax/get.threats.php?severity=all&yearPeriod=all&yearIntervalFrom=2008&monthIntervalFrom=1&yearIntervalTo=2030&monthIntervalTo=12&vendor_name=&software_name=&pageSize=10&PAGEN_1="

# Función para obtener los vendedores de una URL y realizar las transformaciones
async def get_vendors(url, session):
    async with session.get(url, ssl=False) as response:
        if response.status == 200:
            print(f"Procesando: {url}")
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            vendor_labels = soup.find_all('td', text="Vendor:")
            vendors = {label.find_next('td').text.strip() for label in vendor_labels}
            
            # Dividir el texto del vendedor en diferentes vendedores cuando hay comas (",")
            split_vendors = set()
            for vendor in vendors:
                vendor_parts = [part.strip() for part in vendor.split(',')]
                split_vendors.update(vendor_parts)
            
            # Eliminar "Inc" o "Inc." al final del nombre del vendedor
            cleaned_vendors = {vendor[:-4] if vendor.endswith(" Inc") else vendor for vendor in split_vendors}
            cleaned_vendors = {vendor[:-4] if vendor.endswith(" Inc.") else vendor for vendor in cleaned_vendors}
            
            # Eliminar espacios en blanco iniciales y finales
            cleaned_vendors = {vendor.strip() for vendor in cleaned_vendors}
            
            print("\nVendedores encontrados en", url, ":")
            for vendor in cleaned_vendors:
                print(vendor)
            
            return cleaned_vendors
        else:
            print(f"No se pudo obtener la página {url}. Código de estado:", response.status)
            return set()

async def main():
    # Crear una sesión de aiohttp
    async with aiohttp.ClientSession() as session:
        # Crear un conjunto para almacenar los resultados únicos de todas las páginas
        total_results = set()
        
        # Iterar a través de las páginas del 1 al 58
        for page in range(1, 59):  # Cambiar el rango según sea necesario
            url = base_url + str(page)
            
            # Obtener los vendedores de la página actual y aplicar las transformaciones
            vendors = await get_vendors(url, session)
            total_results.update(vendors)
        
        # Imprimir la lista de vendedores únicos de todas las páginas
        print("\nVendedores únicos encontrados en todas las páginas:")
        for vendor in total_results:
            print(vendor)
        
        # Calcular la longitud numérica total de vendedores únicos
        total_unique_vendors = len(total_results)
        print("\nLongitud numérica total de vendedores únicos:", total_unique_vendors)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())