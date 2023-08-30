import os
import re

# Root directory of the local repository
root_directory = '/Users/retr02332/Vulnerability-Disclosures'

# Regular expression to find Discovery Credits in Markdown files
discovery_credits_pattern = re.compile(r'##\s*Discovery\s+Credits\n(.*?)(?=\n##|\Z)', re.IGNORECASE | re.DOTALL)

# Function to find researchers in a file
def find_researchers_in_file(file_path):
    researchers = set()
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
        credits_matches = re.finditer(discovery_credits_pattern, content)
        for credits_match in credits_matches:
            credits_content = credits_match.group(1)
            # Utilizar una expresión regular para encontrar líneas que comiencen con guión o asterisco
            researcher_lines = re.findall(r'[-*]\s*(.*?)\n', credits_content, re.IGNORECASE)
            researchers.update(researcher_lines)
    return researchers

# Lista para almacenar investigadores limpios
cleaned_researchers = set()

# Recursively traverse the root directory
for current_directory, subdirectories, files in os.walk(root_directory):
    # Elimina directorios que comienzan con un punto "."
    subdirectories[:] = [d for d in subdirectories if not d.startswith('.')]
    
    for file in files:
        if file.endswith('.md'):
            full_file_path = os.path.join(current_directory, file)
            researchers_in_file = find_researchers_in_file(full_file_path)
            if researchers_in_file:
                for researcher in researchers_in_file:
                    cleaned_researcher = researcher.split(',', 1)[0].lstrip('- ').strip()
                    cleaned_researchers.add(cleaned_researcher)

# Imprimir los investigadores únicos
for researcher in cleaned_researchers:
    print(researcher)

# Imprimir la cantidad total de investigadores únicos
print("\nCantidad total de investigadores únicos:", len(cleaned_researchers))