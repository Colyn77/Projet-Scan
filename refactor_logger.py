#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ce script parcourt tous les fichiers .py du répertoire courant (et sous-répertoires sauf venv/)
et remplace automatiquement :
- 'import logging' ou 'from logging import getLogger' par 'from utils.logger import get_logger'
- 'get_logger("NOM")' par 'get_logger("NOM")'
"""

import os
import re

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    modified = False

    # Si on trouve logging.getLogger, on remplace par get_logger
    if 'logging.getLogger' in content:
        # Remplacer get_logger("NOM") par get_logger("NOM")
        content = re.sub(r'logging\.getLogger\s*\(\s*([^)]+)\s*\)', r'get_logger(\1)', content)
        modified = True

        # Remplacer "import logging" par "from utils.logger import get_logger"
        if re.search(r'^\s*import\s+logging\s*$', content, flags=re.MULTILINE):
            content = re.sub(r'^\s*import\s+logging\s*$', 'from utils.logger import get_logger', content, flags=re.MULTILINE)
            modified = True

        # Remplacer "from logging import getLogger" par "from utils.logger import get_logger"
        if re.search(r'^\s*from\s+logging\s+import\s+getLogger\s*$', content, flags=re.MULTILINE):
            content = re.sub(r'^\s*from\s+logging\s+import\s+getLogger\s*$', 'from utils.logger import get_logger', content, flags=re.MULTILINE)
            modified = True

        # S’assurer de l’import get_logger s’il n’existe plus
        if 'get_logger' in content and 'from utils.logger import get_logger' not in content:
            content = 'from utils.logger import get_logger\n' + content
            modified = True

    if modified:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Modifié : {filepath}")

def main():
    for root, dirs, files in os.walk('.'):
        # Ignorer le dossier venv
        if 'venv' in root.split(os.sep):
            continue
        for file in files:
            if file.endswith('.py'):
                process_file(os.path.join(root, file))

if __name__ == "__main__":
    main()

