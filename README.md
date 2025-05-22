# 🛠️ Toolbox de Scan de Vulnérabilités

## 📌 Présentation

Cette toolbox a pour objectif de centraliser et d’automatiser plusieurs tests d’intrusion sur des cibles réseau et web. Elle est conçue pour les analystes SOC et pentesters, avec une interface FastAPI permettant de piloter les scans via des requêtes HTTP.

## 🚀 Fonctionnalités principales

- 🔎 Scan réseau via Nmap
- 🌐 Scan de vulnérabilités web (OWASP)
- 🧠 Détection automatique de services et déclenchement des modules associés
- 📁 Génération de rapports
- 🧰 Modules extensibles (plug & play)

## 🧱 Architecture


- Tous les modules sont accessibles via des endpoints REST.
- Le backend pilote les scripts en subprocess ou via des bindings Python.

## 📂 Structure du projet


## 🧪 Installation

```bash
git clone https://github.com/tonrepo/toolbox-scan.git
cd toolbox-scan
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

