#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ce script parcourt tous les fichiers .py du projet (sauf 'utils/logger.py' lui-même)
et remplace chaque occurrence de :
    logger = get_logger("batch_update_loggers")
par :
    logger = get_logger("nom_du_module")
où nom_du_module est le nom du fichier sans l'extension .py.
"""

import os
import re

def process_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    filename = os.path.basename(path)
    module_name, ext = os.path.splitext(filename)
    if ext != '.py':
        return False

    changed = False
    new_lines = []
    for line in lines:
        # On cherche exactement "logger = get_logger(__name__)" (éventuellement avec espaces)
        m = re.match(r'^(\s*)logger\s*=\s*get_logger\s*\(\s*__name__\s*\)\s*$', line)
        if m:
            indent = m.group(1)
            new_line = f'{indent}logger = get_logger("{module_name}")\n'
            new_lines.append(new_line)
            changed = True
        else:
            new_lines.append(line)

    if changed:
        with open(path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        print(f"Modifié : {path}")
    return changed

def main():
    root = os.getcwd()
    for dirpath, dirnames, filenames in os.walk(root):
        # Ignorer le venv et utils/logger.py (déjà corrigé)
        if 'venv' in dirpath.split(os.sep):
            continue
        if os.path.relpath(dirpath, root).startswith('utils'):
            # On ne change pas utils/logger.py
            continue

        for fname in filenames:
            if not fname.endswith('.py'):
                continue
            fullpath = os.path.join(dirpath, fname)
            process_file(fullpath)

if __name__ == "__main__":
    main()
