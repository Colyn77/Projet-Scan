import nmap
from utils.logger import get_logger

# Configuration du logger
logger = get_logger('port_scanner')

def scan_ports(target: str, ports: str = "1-1024", scan_type: str = "-sT"):
    """
    Scan des ports ouverts sur une cible avec Nmap.

    :param target: IP ou domaine cible
    :param ports: Plage de ports à scanner (ex: "22,80,443" ou "1-65535")
    :param scan_type: Type de scan (ex: "-sS" pour SYN scan, "-sV" pour détection des services)
    :return: Dictionnaire avec les résultats du scan
    """
    logger.info(f"Démarrage du scan de ports sur {target}")
    logger.debug(f"Ports: {ports}, Type de scan: {scan_type}")
    
    try:
        nm = nmap.PortScanner()
        logger.info(f"Scan en cours sur {target}, ports : {ports} ({scan_type})...")

        nm.scan(hosts=target, ports=ports, arguments=scan_type)

        results = []
        open_ports_count = 0
        
        for host in nm.all_hosts():
            logger.debug(f"Analyse de l'hôte: {host}")
            
            for proto in nm[host].all_protocols():
                logger.debug(f"Protocole: {proto}")
                
                for port in nm[host][proto]:
                    state = nm[host][proto][port]["state"]
                    service = nm[host][proto][port].get("name", "Unknown")
                    
                    port_info = {
                        "ip": host,
                        "port": port,
                        "state": state,
                        "service": service
                    }
                    results.append(port_info)
                    
                    if state == "open":
                        open_ports_count += 1
                        logger.info(f"Port ouvert trouvé: {port}/{proto} - Service: {service}")
                    else:
                        logger.debug(f"Port {port}/{proto}: {state}")

        logger.info(f"Scan terminé: {open_ports_count} ports ouverts trouvés sur {len(results)} ports scannés")
        return results
        
    except Exception as e:
        logger.error(f"Erreur lors du scan de ports: {e}", exc_info=True)
        raise

# Test rapide si le script est exécuté directement
if __name__ == "__main__":
    logger.info("Exécution du test de scan de ports")
    target_ip = input("Entrez l'adresse IP cible : ")
    
    try:
        scan_results = scan_ports(target_ip)
        for r in scan_results:
            print(f"IP: {r['ip']} | Port: {r['port']} | État: {r['state']} | Service: {r['service']}")
        logger.info("Test terminé avec succès")
    except Exception as e:
        logger.error(f"Erreur lors du test: {e}", exc_info=True)
