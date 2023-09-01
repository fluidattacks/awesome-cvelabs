import requests
from bs4 import BeautifulSoup

url = "https://labs.cyberark.com/cyberark-labs-security-advisories/"
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0"
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    soup = BeautifulSoup(response.text, "html.parser")
    
    table = soup.find("table", {"id": "tableOne"})

    if table:
        cve_set = set()
        researchers_set = set()
        vendors_set = set()

        rows = table.find_all("tr")
        for row in rows[1:]:  # Omitir la primera fila que contiene encabezados
            cells = row.find_all("td")
            if len(cells) >= 9:
                cve_set.add(cells[2].text.strip())
                researchers_set.add(cells[6].text.strip())
                vendors_set.add(cells[3].text.strip())

        total_cves = len(cve_set)
        total_researchers = len(researchers_set)
        total_vendors = len(vendors_set)

        print(f"Total de CVE's únicos: {total_cves}")
        print(f"Total de investigadores únicos: {total_researchers}")
        print(f"Total de proveedores únicos: {total_vendors}")
    else:
        print("No se encontró la tabla con el ID especificado.")
else:
    print(f"Error al hacer la solicitud: {response.status_code}")