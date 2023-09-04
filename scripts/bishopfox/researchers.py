import requests
from bs4 import BeautifulSoup

base_url = "https://bishopfox.com/blog/advisories?page="
researchers = set()

for page in range(1, 7):
    url = base_url + str(page)
    response = requests.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        researcher_elements = soup.find_all("p", class_="mt-6 text-copy-sm text-dark-gray")
        
        for element in researcher_elements:
            researcher_name = element.find("span").text.strip()
            researchers.add(researcher_name)

# Imprimir los investigadores únicos encontrados
print("Investigadores encontrados:")
for researcher in researchers:
    print(researcher)

print("\nTotal investigadores: " + str(len(researchers)))