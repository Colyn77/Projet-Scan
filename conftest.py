# conftest.py
import sys
import os

# Ajoute le dossier racine du projet (le parent de conftest.py) à PYTHONPATH
PROJECT_ROOT = os.path.dirname(__file__)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
