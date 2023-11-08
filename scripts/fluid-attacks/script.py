import aiohttp
import asyncio
import re
import json

base_url = "https://gitlab.com/fluidattacks/universe/-/refs/trunk/logs_tree/airs/front/content/pages/advisories?format=json&offset={offset}&ref_type=heads"
advisory_base_url = "https://gitlab.com/fluidattacks/universe/-/raw/trunk/airs/front/content/pages/advisories/{filename}/index.md?ref_type=heads&inline=true"

async def parse_advisory(session, advisory_url):
    async with session.get(advisory_url) as response:
        if response.status == 200:
            advisory_text = await response.text()

            # Buscar el encabezado YAML
            start_index = advisory_text.find("---")
            end_index = advisory_text.find("---", start_index + 3)
            header_text = advisory_text[start_index:end_index + 3]

            header_lines = header_text.split("\n")[1:-1]
            header = {}
            for line in header_lines:
                if ":" in line:
                    key, value = line.split(":", 1)
                    header[key.strip()] = value.strip()

            # Buscar la URL del vendedor en la sección "References"
            vendor_url = re.search(r'\*\*Vendor page\*\* <(.*?)>', advisory_text)
            if vendor_url:
                vendor = vendor_url.group(1)
            else:
                vendor = ''

            # Agregar el vendedor al JSON
            header['Vendor'] = vendor

            return header
        else:
            return None

async def get_advisory_names(session, base_url):
    async with session.get(base_url) as response:
        if response.status == 200:
            data = await response.text()
            json_data = json.loads(data)
            advisory_names = [item['file_name'] for item in json_data]
            return advisory_names
        else:
            return []

async def main():
    async with aiohttp.ClientSession() as session:
        advisory_names = []
        offset = 0
        while True:
            current_base_url = base_url.format(offset=offset)
            names = await get_advisory_names(session, current_base_url)
            if not names:
                break
            advisory_names.extend(names)
            offset += 25

        cves = set()
        vendors = set()
        authors = set()

        for name in advisory_names:
            advisory_url = advisory_base_url.format(filename=name)
            advisory_data = await parse_advisory(session, advisory_url)
            if advisory_data:
                cve_ids = advisory_data.get('cveid', '').split(',')
                cves.update(cve_ids)
                vendors.add(advisory_data.get('Vendor', ''))
                author = advisory_data.get('authors', '')
                if author != "Fake Author":
                    if author.find('&') != -1:
                        author_list = [a.strip() for a in author.split('&')]
                        authors.update(author_list)
                    else:
                        authors.add(author)
        
        cves.discard('')
        vendors.discard('')
        authors.discard('')
                
        total_cves = len(cves)
        total_vendors = len(vendors)
        total_authors = len(authors)

        print(f"Total de CVE's únicos: {total_cves}")
        print(f"Total de vendors únicos: {total_vendors}")
        print(f"Total de researchers únicos: {total_authors}")

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
