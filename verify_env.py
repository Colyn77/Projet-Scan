# verify_env.py
import importlib
import sys

modules = [
    "flask", "jinja2", "werkzeug", "itsdangerous", "click", "blinker", "MarkupSafe",
    "python_nmap", "scapy", "psutil", "tqdm",
    "cryptography", "bcrypt", "requests",
    "dotenv", "zipp", "importlib_metadata"
]

missing = []

print("🔍 Vérification des dépendances...")

for module in modules:
    try:
        importlib.import_module(module)
        print(f"✅ {module} OK")
    except ImportError:
        print(f"❌ {module} manquant")
        missing.append(module)

if missing:
    print("\n⚠️ Modules manquants :")
    for m in missing:
        print(f"  - {m}")
    print("\n➡️ Tu peux les installer avec :")
    print(f"pip install {' '.join(missing)}")
else:
    print("\n🎉 Tous les modules requis sont installés !")
