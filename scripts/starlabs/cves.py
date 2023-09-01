import requests
from bs4 import BeautifulSoup
import re

# Define the base URL
base_url = 'https://starlabs.sg/advisories/page/'

# Initialize a set to store unique CVEs
unique_cves = set()

# Add page number 1 to the list of pages to process
url_page_1 = 'https://starlabs.sg/advisories/'
unique_cves.update(re.findall(r'\(CVE-\d{4}-\d{4,5}\)', requests.get(url_page_1).text))

# Iterate through pages 2 to 17
for page_num in range(2, 18):
    # Build the URL for the current page
    url = f'{base_url}{page_num}/'

    # Make a GET request to the URL
    response = requests.get(url)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content of the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all the CVE matches in the text of the page
        cves_found = re.findall(r'\(CVE-\d{4}-\d{4,5}\)', soup.get_text())

        # Add the found CVEs to the set of unique CVEs
        unique_cves.update(cves_found)
    else:
        print(f'Error fetching page {url}')

# Calculate the total number of unique CVEs captured
total_unique_cves = len(unique_cves)

# Print the result
print(f'Total {total_unique_cves} unique CVEs captured in total.')

# If you wish, you can print the list of unique CVEs
print('Unique CVEs:')
for cve in unique_cves:
    print(cve)
print("Unique CVEs: ", len(unique_cves))
