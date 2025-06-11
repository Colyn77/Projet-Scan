#!/bin/bash

echo "📦 Installation des dépendances..."

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages colorés
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Vérifier si Nmap est installé
if ! command -v nmap &> /dev/null; then
    print_status "Nmap non trouvé. Installation en cours..."
    sudo apt update && sudo apt install -y nmap
else
    print_success "Nmap est déjà installé."
fi

# Installer Python et pip s'ils ne sont pas présents
if ! command -v python3 &> /dev/null; then
    print_status "Python3 non trouvé. Installation en cours..."
    sudo apt install -y python3 python3-pip
else
    print_success "Python3 est déjà installé."
fi

# Créer un environnement virtuel (optionnel mais recommandé)
if [ ! -d "venv" ]; then
    print_status "Création de l'environnement virtuel..."
    python3 -m venv venv
    source venv/bin/activate
else
    print_success "Environnement virtuel déjà existant."
    source venv/bin/activate
fi

# Installer les dépendances systèmes nécessaires à Scapy
print_status "Installation des dépendances système pour le sniffing réseau avec Scapy..."
sudo apt install -y tcpdump libpcap-dev
sudo apt-get install tshark
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Installation Hydra
print_status "Installation d'Hydra pour brute-force..."
sudo apt install -y hydra

# Installation Nuclei
print_status "Installation de Nuclei (Scanner web)..."
ARCH=$(uname -m)
[ "$ARCH" = "x86_64" ] && ARCH="amd64"
[ "$ARCH" = "aarch64" ] && ARCH="arm64"

LATEST=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d '"' -f 4)
NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${LATEST}/nuclei_${LATEST#v}_linux_${ARCH}.zip"

mkdir -p bin generated_reports/nuclei services routes
cd bin
curl -sL "$NUCLEI_URL" -o nuclei.zip && unzip -o nuclei.zip && rm nuclei.zip && chmod +x nuclei
cd ..

# Templates Nuclei
if [ ! -d "nuclei-templates" ]; then
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git
fi

# Fichiers __init__.py
touch services/__init__.py routes/__init__.py

if ./bin/nuclei -version > /dev/null 2>&1; then
    print_success "Nuclei installé ✓"
else
    print_error "Erreur installation Nuclei"
fi

# Installation Metasploit 
print_status "Installation de Metasploit Framework"
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
chmod 755 msfinstall && \
./msfinstall

# Initialiser la DB Metasploit                                                                                
sudo msfdb init 

# Vérifier que ça marche
sudo msfdb status

# Créer les dossiers nécessaires
mkdir -p results credentials forensics rapport sauvegarde timeline/archives generated_reports wordlists exploit_reports scan_results scripts vuln_reports malware logs

print_success "Dossiers créés."

# Générer la clé de chiffrement si absente
if [ ! -f "secret.key" ]; then
    print_status "Clé secrète absente. Génération..."
    python3 -c "from cryptography.fernet import Fernet; open('secret.key', 'wb').write(Fernet.generate_key())"
    print_success "Clé secrète générée dans secret.key"
else
    print_success "Clé secrète déjà présente."
fi

# === Pare-feu (UFW) ===
read -p "🔐 Souhaitez-vous configurer un firewall UFW (linux) ? (y/n) " answer
if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
    if ! command -v ufw &> /dev/null; then
        print_status "UFW non trouvé. Installation..."
        sudo apt install -y ufw
    fi

    print_status "Application des règles UFW..."

    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow from 192.168.0.0/16 to any port 5000
    sudo ufw allow 22  # SSH
    sudo ufw allow 443
    sudo ufw allow 5432
    sudo ufw --force enable

    print_success "UFW configuré : seul le réseau local peut accéder à Flask (port 5000)"
fi

# Installer les dépendances Python
print_status "Installation des paquets Python..."
pip install -r requirements.txt

# Vérifications finales
print_status "Vérifications finales..."

echo ""
print_success "🎉 Installation terminée !"
echo ""
echo "🚀 Pour lancer la Toolbox :"
echo "1. source venv/bin/activate"
echo "2. python3 app.py"
echo "3. Accès: http://localhost:5000"
echo "4. Nuclei: http://localhost:5000/nuclei"
