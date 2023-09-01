import requests
from bs4 import BeautifulSoup
import re

# Define the base URL
base_url = 'https://starlabs.sg/advisories/page/'

# Initialize a set to store unique researchers
unique_researchers = set()

# Add page number 1 to the list of pages to process
url_page_1 = 'https://starlabs.sg/advisories/'
response_page_1 = requests.get(url_page_1)

# Check if the request for page 1 was successful
if response_page_1.status_code == 200:
    # Parse the HTML content of page 1
    soup_page_1 = BeautifulSoup(response_page_1.text, 'html.parser')

    # Find all the researcher usernames in the footer of page 1
    researchers_found_page_1 = soup_page_1.find_all('footer', class_='entry-footer')
    for researcher_entry in researchers_found_page_1:
        researcher_text = researcher_entry.get_text()
        researcher_match = re.search(r'@([\w]+)', researcher_text)
        if researcher_match:
            researcher_username = researcher_match.group(1)
            unique_researchers.add(researcher_username)

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

        # Find all the researcher usernames in the footer of the page
        researchers_found = soup.find_all('footer', class_='entry-footer')
        for researcher_entry in researchers_found:
            researcher_text = researcher_entry.get_text()
            researcher_match = re.search(r'@([\w]+)', researcher_text)
            if researcher_match:
                researcher_username = researcher_match.group(1)
                unique_researchers.add(researcher_username)
    else:
        print(f'Error fetching page {url}')

# Calculate the total number of unique researchers found
total_unique_researchers = len(unique_researchers)

# Print the result
print(f'Total {total_unique_researchers} unique researchers found in total.')

# If you wish, you can print the list of unique researchers
print('Unique researchers:')
for researcher_username in unique_researchers:
    print(f'@{researcher_username}')