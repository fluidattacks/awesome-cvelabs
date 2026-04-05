python := "nix develop --command python"

# List available recipes
default:
    @just --list

# Run all scrapers and update data.yaml files
scrape:
    for s in scripts/*/scrape.py; do {{python}} "$s"; done

# Run a single lab scraper (e.g. just scrape-one nozomi)
scrape-one lab:
    {{python}} scripts/{{lab}}/scrape.py

# Validate all data.yaml files with Pydantic
validate:
    {{python}} -c "
from lab_model import CVELab
from pathlib import Path
errors = []
for f in sorted(Path('scripts').rglob('data.yaml')):
    try:
        lab = CVELab.from_yaml(f.read_text())
        print(f'OK  {f.parent.name}: A={lab.A} Q={lab.Q}')
    except Exception as e:
        errors.append(f'{f.parent.name}: {e}')
        print(f'ERR {f.parent.name}: {e}')
if errors:
    raise SystemExit(f'{len(errors)} errores de validación')
print(f'\n{38 - len(errors)}/38 OK')
"

# Export JSON Schema from lab_model.py
schema:
    {{python}} lab_model.py > lab_schema.json

# Run the 5 newly migrated test labs (bishopfox, core-security, fluid-attacks, integrity-labs, sentinelone)
scrape-test:
    for lab in bishopfox core-security fluid-attacks integrity-labs sentinelone; do \
        echo "=== $lab ==="; \
        {{python}} scripts/$lab/scrape.py; \
    done

# Run the 5 playwright-migrated scrapers (small labs)
scrape-playwright:
    for lab in securitum wiz assetnote census-labs core-labs; do \
        echo "=== $lab ==="; \
        {{python}} scripts/$lab/scrape.py; \
    done

# Enter the nix dev shell
dev:
    nix develop
