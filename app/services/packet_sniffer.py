from datetime import datetime
import os
import subprocess
import json
import tempfile
from app.utils.logger import get_logger

# Configuration du logger
logger = get_logger('packet_sniffer')

CAPTURE_DIR = "captures"

def get_interfaces():
    """Récupère la liste des interfaces réseau disponibles"""
    logger.info("Récupération des interfaces réseau")
    try:
        # Utiliser la commande ip pour lister les interfaces
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"Erreur lors de l'exécution de ip link show: {result.stderr}")
            return []
            
        interfaces = []
        lines = result.stdout.split('\n')
        
        for line in lines:
            if ': ' in line:
                # Format: 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>...
                parts = line.split(': ')
                if len(parts) >= 2:
                    iface_name = parts[1].split(':')[0]
                    interfaces.append({
                        "name": iface_name,
                        "description": "",
                        "mac": "",
                        "ip": ""
                    })
                    logger.debug(f"Interface trouvée: {iface_name}")
        
        logger.info(f"{len(interfaces)} interfaces trouvées")
        return interfaces
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des interfaces: {e}", exc_info=True)
        return []

def capture_packets(interface="eth0", packet_count=100):
    """
    Capture les paquets réseau
    
    Args:
        interface (str): Interface réseau à utiliser pour la capture
        packet_count (int): Nombre de paquets à capturer
        
    Returns:
        str: Chemin vers le fichier pcap généré
    """
    logger.info(f"Démarrage de la capture sur {interface} - {packet_count} paquets")
    
    # Créer le répertoire de captures s'il n'existe pas
    if not os.path.exists(CAPTURE_DIR):
        os.makedirs(CAPTURE_DIR)
        logger.debug(f"Création du dossier {CAPTURE_DIR}")

    # Générer un nom de fichier unique avec timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_filename = f"{CAPTURE_DIR}/capture_{timestamp}.pcap"
    
    try:
        # Capturer les paquets réseau
        packets = sniff(iface=interface, count=packet_count)
        
        # Enregistrer la capture dans un fichier pcap
        wrpcap(pcap_filename, packets)
        
        logger.info(f"Capture enregistrée : {pcap_filename} ({len(packets)} paquets)")
        return pcap_filename
    except Exception as e:
        logger.error(f"Erreur lors de la capture : {e}", exc_info=True)
        raise

def analyze_pcap(pcap_file):
    """
    Analyse un fichier pcap et extrait les informations importantes
    
    Args:
        pcap_file (str): Chemin vers le fichier pcap à analyser
        
    Returns:
        dict: Informations extraites du fichier pcap
    """
    logger.info(f"Début de l'analyse du fichier pcap: {pcap_file}")
    
    if not os.path.exists(pcap_file):
        logger.error(f"Fichier pcap introuvable: {pcap_file}")
        raise FileNotFoundError(f"Fichier pcap introuvable: {pcap_file}")
        
    try:
        # Utiliser tshark (wireshark en ligne de commande) pour analyser le pcap
        logger.debug("Extraction des statistiques générales")
        
        # Extraire les statistiques générales
        stats_cmd = [
            "tshark", "-r", pcap_file, 
            "-q", "-z", "io,stat,1", 
            "-z", "conv,ip", 
            "-z", "endpoints,ip"
        ]
        stats_result = subprocess.run(stats_cmd, capture_output=True, text=True)
        
        # Extraire les protocoles utilisés
        logger.debug("Extraction des protocoles")
        protocols_cmd = [
            "tshark", "-r", pcap_file, 
            "-T", "fields", "-e", "frame.protocols"
        ]
        protocols_result = subprocess.run(protocols_cmd, capture_output=True, text=True)
        
        # Extraire les informations de base sur chaque paquet
        logger.debug("Extraction des informations de paquets")
        packets_cmd = [
            "tshark", "-r", pcap_file, 
            "-T", "fields", 
            "-e", "frame.number", "-e", "frame.time", 
            "-e", "ip.src", "-e", "ip.dst", 
            "-e", "_ws.col.Protocol", "-e", "frame.len",
            "-E", "separator=,"
        ]
        packets_result = subprocess.run(packets_cmd, capture_output=True, text=True)
        
        # Extraire les ports utilisés
        logger.debug("Extraction des ports")
        ports_cmd = [
            "tshark", "-r", pcap_file, 
            "-T", "fields", 
            "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport"
        ]
        ports_result = subprocess.run(ports_cmd, capture_output=True, text=True)
        
        # Analyser les résultats
        protocols = set()
        for line in protocols_result.stdout.splitlines():
            if line:
                for proto in line.split(':'):
                    protocols.add(proto)
        
        packets = []
        for line in packets_result.stdout.splitlines():
            if line:
                parts = line.split(',')
                if len(parts) >= 6:
                    try:
                        packet = {
                            "number": parts[0],
                            "time": parts[1],
                            "src": parts[2],
                            "dst": parts[3],
                            "protocol": parts[4],
                            "length": parts[5]
                        }
                        packets.append(packet)
                    except Exception as e:
                        logger.warning(f"Impossible de parser la ligne de paquet: {line} - {e}")
        
        # Extraire les ports utilisés
        tcp_ports = set()
        udp_ports = set()
        for line in ports_result.stdout.splitlines():
            if line:
                parts = line.split('\t')
                for part in parts:
                    if part and part != "":
                        try:
                            port = int(part)
                            if port > 0:
                                if parts.index(part) < 2:  # Les deux premiers champs sont TCP
                                    tcp_ports.add(port)
                                else:  # Les deux derniers champs sont UDP
                                    udp_ports.add(port)
                        except (ValueError, IndexError):
                            pass
        
        # Analyser les adresses IP uniques
        ip_addresses = set()
        for packet in packets:
            if packet.get("src"):
                ip_addresses.add(packet.get("src"))
            if packet.get("dst"):
                ip_addresses.add(packet.get("dst"))
        
        # Trouver les 3 protocoles les plus courants
        protocol_counts = {}
        for packet in packets:
            proto = packet.get("protocol", "")
            if proto:
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        
        top_protocols = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        
        # Calculer la taille moyenne des paquets
        total_size = 0
        for packet in packets:
            try:
                total_size += int(packet.get("length", 0))
            except (ValueError, TypeError):
                pass
        
        avg_packet_size = total_size / len(packets) if packets else 0
        
        # Construire le résultat
        analysis_result = {
            "file": pcap_file,
            "packet_count": len(packets),
            "unique_ips": len(ip_addresses),
            "ip_addresses": list(ip_addresses),
            "protocols": list(protocols),
            "top_protocols": top_protocols,
            "avg_packet_size": round(avg_packet_size, 2),
            "tcp_ports": sorted(list(tcp_ports)),
            "udp_ports": sorted(list(udp_ports)),
            "first_packets": packets[:5] if len(packets) > 5 else packets,
            "capture_duration": stats_result.stdout
        }
        
        logger.info(f"Analyse terminée: {len(packets)} paquets analysés, {len(ip_addresses)} IPs uniques")
        logger.debug(f"Protocoles trouvés: {protocols}")
        return analysis_result
        
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse du fichier pcap: {e}", exc_info=True)
        # En cas d'erreur, retourner une analyse basique
        return {
            "file": pcap_file,
            "packet_count": 0,
            "error": str(e),
            "note": "L'analyse détaillée n'a pas pu être effectuée. Vous pouvez toujours télécharger le fichier pcap pour l'analyser manuellement."
        }

# Importer ces fonctions seulement si nécessaire
try:
    from scapy.all import sniff, wrpcap
    USE_SCAPY = True
    logger.info("Scapy est disponible - utilisation pour la capture")
except ImportError:
    USE_SCAPY = False
    logger.warning("Scapy n'est pas installé. Utilisation de TCPDump comme alternative.")
    
    def capture_packets(interface="eth0", packet_count=100):
        """
        Capture les paquets réseau en utilisant tcpdump
        
        Args:
            interface (str): Interface réseau à utiliser pour la capture
            packet_count (int): Nombre de paquets à capturer
            
        Returns:
            str: Chemin vers le fichier pcap généré
        """
        logger.info(f"Démarrage de la capture TCPDump sur {interface} - {packet_count} paquets")
        
        # Créer le répertoire de captures s'il n'existe pas
        if not os.path.exists(CAPTURE_DIR):
            os.makedirs(CAPTURE_DIR)
            logger.debug(f"Création du dossier {CAPTURE_DIR}")

        # Générer un nom de fichier unique avec timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_filename = f"{CAPTURE_DIR}/capture_{timestamp}.pcap"
        
        try:
            # Utiliser tcpdump pour la capture
            cmd = [
                "sudo", "tcpdump", 
                "-i", interface, 
                "-c", str(packet_count),
                "-w", pcap_filename
            ]
            
            logger.info(f"Exécution de la commande: {' '.join(cmd)}")
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode != 0:
                logger.error(f"Erreur tcpdump: {process.stderr}")
                raise Exception(f"Échec de la capture : {process.stderr}")
                
            logger.info(f"Capture enregistrée : {pcap_filename}")
            return pcap_filename
        except Exception as e:
            logger.error(f"Erreur lors de la capture : {e}", exc_info=True)
            raise

if __name__ == "__main__":
    # Test de la fonction de capture
    logger.info("Démarrage du test du module packet_sniffer")
    interfaces = get_interfaces()
    print("Interfaces disponibles :")
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface['name']}")
    
    # Utiliser l'interface par défaut
    capture_file = capture_packets(interface="eth0", packet_count=10)
    print(f"Capture enregistrée dans : {capture_file}")
    
    # Analyser le fichier
    analysis = analyze_pcap(capture_file)
    print("Résultats de l'analyse :")
    print(json.dumps(analysis, indent=2))
    
    logger.info("Test terminé")
