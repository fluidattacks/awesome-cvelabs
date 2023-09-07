import requests
import json
import re

# URL de la API
url = "https://bugs.chromium.org/prpc/monorail.Issues/ListIssues"

# Encabezados de la solicitud
headers = {
    "Host": "bugs.chromium.org",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-Xsrf-Token": "b4ATlYQFxeLFCGURol_xJjoxNjk0MDM2Njcx",
    "Origin": "https://bugs.chromium.org",
    "Cache-Control": "no-cache",
}

# Datos de la solicitud
data = {
    "projectNames": ["project-zero"],
    "query": "",
    "cannedQuery": 1,
    "pagination": {"maxItems": 10000}
}

# Realizar la solicitud POST
response = requests.post(url, json=data, headers=headers)

# Verificar si la solicitud fue exitosa
if response.status_code == 200:
    # Eliminar el prefijo no válido del JSON
    json_content = response.text.lstrip(")]}'")
    
    # Ahora puedes analizar el JSON correctamente
    json_response = json.loads(json_content)
    
    # Inicializar conjuntos para almacenar vendors, researchers y CVEs únicos
    unique_vendors = set()
    unique_researchers = set()
    unique_cves = set()

    # Expresión regular para buscar CVEs
    cve_pattern = r'CVE-\d{4}-\d{4,5}'
    
    # Iterar a través de las issues en la respuesta
    for issue in json_response.get("issues", []):
        # Extraer los labels
        labels = issue.get("labelRefs", [])
        for label in labels:
            label_text = label.get("label", "")
            
            # Extraer vendors
            if label_text.startswith("Vendor-"):
                vendor = label_text.split("-")[1]
                unique_vendors.add(vendor)
            
            # Extraer researchers
            elif label_text.startswith("Finder-"):
                researcher = label_text.split("-")[1]
                unique_researchers.add(researcher)
            
            # Buscar CVEs utilizando regex
            cves = re.findall(cve_pattern, label_text)
            unique_cves.update(cves)

    # Calcular la cantidad total de vendors, researchers y CVEs únicos
    total_unique_vendors = len(unique_vendors)
    total_unique_researchers = len(unique_researchers)
    total_unique_cves = len(unique_cves)

    print(f"Total de vendors únicos: {total_unique_vendors}")
    print(f"Total de researchers únicos: {total_unique_researchers}")
    print(f"Total de CVEs únicos: {total_unique_cves}")

else:
    print(f"La solicitud falló con el código de estado: {response.status_code}")