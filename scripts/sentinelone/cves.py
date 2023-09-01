import requests
import re

# URL del sitio web
url = 'https://www.sentinelone.com/labs/our-cves/'

# Realizar una solicitud GET a la página web
response = requests.get(url)

# Verificar si la solicitud fue exitosa
if response.status_code == 200:
    # Obtener el contenido de la página web
    page_content = response.text

    # Utilizar una expresión regular para encontrar CVEs en el contenido
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cves = re.findall(cve_pattern, page_content)

    # Eliminar duplicados si es necesario
    cves = list(set(cves))

    # Imprimir los CVEs encontrados
    for cve in cves:
        print(cve)
    print("Total CVE's: ",len(cves))
else:
    print('Error al obtener la página:', response.status_code)