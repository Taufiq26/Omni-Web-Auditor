#!/usr/bin/env python3
"""Entry point Omni-Web-Auditor (CLI `audit`).

Contoh:
    python audit.py init proyek-x --target https://staging.proyek-x.com --intrusive
    python audit.py run proyek-x --allow-intrusive --endpoints-file endpoints.json
    python audit.py checklist proyek-x
    python audit.py mark WSTG-ATHN-03 --name proyek-x --status pass --evidence shot.png
    python audit.py verdict proyek-x
    python audit.py signoff proyek-x --name-signer "Nama Penguji"
    python audit.py report proyek-x
"""

from src.cli.app import main

if __name__ == "__main__":
    main()
