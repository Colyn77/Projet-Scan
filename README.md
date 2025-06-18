# 🛠️ Toolbox de Scan de Vulnérabilités

## 📌 Présentation

Cette toolbox a pour objectif de centraliser et d’automatiser plusieurs tests d’intrusion sur des cibles réseau et web. Elle est conçue pour les analystes SOC et pentesters, avec une interface Flask permettant de piloter les scans via des requêtes HTTP.

## 🚀 Fonctionnalités principales

- 🔎 Scan réseau via Nmap
- 🌐 Scan de vulnérabilités web (Nuclei) & Systeme (Nmap NSE)
- 🦈 Capture réseau via WireShark
- 🔒 Brute Force via Hydra
- 🧠 Détection automatique de services et déclenchement des modules associés
- 📁 Génération de rapports
- 🧰 Modules extensibles (plug & play)

## 🧱 Architecture


- Tous les modules sont accessibles via des endpoints REST.
- Le backend pilote les scripts en subprocess ou via des bindings Python.

## 📂 Structure du projet


## 🧪 Installation

```bash
git clone https://github.com/Colyn77/Projet-Scan
cd Projet-Scan
./install.sh
source venv/bin/activate (si environnement virtuel voulu)
python3 app.py

