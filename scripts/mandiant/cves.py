import os
import re

# Root directory of the local repository
root_directory = '/Users/retr02332/Vulnerability-Disclosures'

# Regular expression to find CVEs in Markdown files
cve_pattern = re.compile(r'cve-\d{4}-\d{4,5}', re.IGNORECASE)

# Function to find CVEs in a file
def find_cves_in_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
        found_cves = re.findall(cve_pattern, content)
        return found_cves

# Use a set to store the found CVEs
cves = set()

# Recursively traverse the root directory
for current_directory, subdirectories, files in os.walk(root_directory):
    # Elimina directorios que comienzan con un punto "."
    subdirectories[:] = [d for d in subdirectories if not d.startswith('.')]
    
    for file in files:
        if file.endswith('.md'):
            full_file_path = os.path.join(current_directory, file)
            cves_in_file = find_cves_in_file(full_file_path)
            if cves_in_file:
                cves.update(cves_in_file)

# Obtener la cantidad de CVEs únicos encontrados
num_unique_cves = len(cves)

# Imprimir la cantidad de CVEs únicos encontrados
print(f'Cantidad de CVEs únicos encontrados: {num_unique_cves}')
