#!/bin/bash

echo "📦 Installation des dépendances..."

# Vérifier si Nmap est installé
if ! command -v nmap &> /dev/null; then
    echo "🔍 Nmap non trouvé. Installation en cours..."
    sudo apt update && sudo apt install -y nmap
else
    echo "✅ Nmap est déjà installé."
fi

# Installer Python et pip s'ils ne sont pas présents
if ! command -v python3 &> /dev/null; then
    echo "🐍 Python3 non trouvé. Installation en cours..."
    sudo apt install -y python3 python3-pip
else
    echo "✅ Python3 est déjà installé."
fi

# Créer un environnement virtuel (optionnel mais recommandé)
if [ ! -d "venv" ]; then
    echo "📦 Création de l'environnement virtuel..."
    python3 -m venv venv
    source venv/bin/activate
else
    echo "✅ Environnement virtuel déjà existant."
    source venv/bin/activate
fi

# Installer les dépendances systèmes nécessaires à Scapy

echo "📦 Installation des dépendances système pour le sniffing réseau avec Scapy..."
sudo apt install -y tcpdump libpcap-dev
sudo apt-get install tshark
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Installation Hydra

echo "📦 Installation d'Hydra pour brute-force..."
sudo apt install -y hydra

# Installation Metasploit 

echo "📦 Installation de Metasploit Framework"
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
chmod 755 msfinstall && \
./msfinstall

# Créer les dossiers nécessaires
mkdir -p results credentials forensics rapport sauvegarde
echo "✅ Dossiers créés : results/, credentials/, forensics/, rapport/, sauvegarde/"

# Générer la clé de chiffrement si absente
if [ ! -f "secret.key" ]; then
    echo "🔐 Clé secrète absente. Génération..."
    python3 -c "from cryptography.fernet import Fernet; open('secret.key', 'wb').write(Fernet.generate_key())"
    echo "✅ Clé secrète générée dans secret.key"
else
    echo "🔐 Clé secrète déjà présente."
fi

# === Pare-feu (UFW) ===
read -p "🔐 Souhaitez-vous configurer un firewall UFW (linux) ? (y/n) " answer
if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
    if ! command -v ufw &> /dev/null; then
        echo "🔧 UFW non trouvé. Installation..."
        sudo apt install -y ufw
    fi

    echo "🛡 Application des règles UFW..."

    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow from 192.168.0.0/16 to any port 5000
    sudo ufw allow 22  # SSH
    sudo ufw allow 443
    sudo ufw --force enable

    echo "✅ UFW configuré : seul le réseau local peut accéder à Flask (port 5000)"
fi

# Installer les dépendances Python
echo "📜 Installation des paquets Python..."
pip install -r requirements.txt

echo "🚀 Installation terminée ! Pour lancer l'API :"
echo "1. Active l'environnement : source venv/bin/activate"
echo "2. Lance : python3 app.py"
