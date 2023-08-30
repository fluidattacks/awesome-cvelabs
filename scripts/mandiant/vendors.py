import os
import re

# Directorio raíz del repositorio local
root_directory = '/Users/retr02332/Vulnerability-Disclosures'

# Expresión regular para encontrar "vendors" en archivos Markdown
vendor_pattern = re.compile(r'reported to\s+(.*?)\n', re.IGNORECASE)

# Conjunto para almacenar los "vendors" únicos
unique_vendors = set()

# Recorrer de manera recursiva el directorio raíz
for current_directory, subdirectories, files in os.walk(root_directory):
    # Eliminar directorios que comiencen con un punto "."
    subdirectories[:] = [d for d in subdirectories if not d.startswith('.')]
    
    for file in files:
        if file.endswith('.md'):
            full_file_path = os.path.join(current_directory, file)
            with open(full_file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                # Buscar "vendors" en el contenido del archivo
                vendors = re.findall(vendor_pattern, content)
                unique_vendors.update(vendors)

# Imprimir la lista única de "vendors" encontrados
for vendor in unique_vendors:
    print(vendor.strip())  # Eliminar espacios en blanco adicionales alrededor del nombre del "vendor"
print("len vendors: "+str(len(unique_vendors)))