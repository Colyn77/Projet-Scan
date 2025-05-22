import nmap
from app.utils.logger import get_logger

# Configuration du logger
logger = get_logger('network_discovery')

def discover_network(network_range: str):
    """
    Scanne un réseau donné et retourne la liste des machines actives.
    """
    logger.info(f"Démarrage de la découverte du réseau: {network_range}")
    
    try:
        nm = nmap.PortScanner()
        logger.debug(f"Scan du réseau {network_range} avec arguments: -sP")
        
        nm.scan(hosts=network_range, arguments="-sP")  # Scan sans port (découverte simple)
        
        active_hosts = []
        total_hosts = len(nm.all_hosts())
        logger.info(f"{total_hosts} hôtes trouvés")
        
        for host in nm.all_hosts():
            host_info = {
                "ip": host,
                "state": nm[host].state(),
                "hostname": nm[host].hostname()
            }
            active_hosts.append(host_info)
            logger.debug(f"Hôte découvert: IP={host}, hostname={host_info['hostname']}, state={host_info['state']}")
        
        logger.info(f"Découverte terminée: {len(active_hosts)} hôtes actifs trouvés")
        return active_hosts
        
    except Exception as e:
        logger.error(f"Erreur lors de la découverte du réseau: {e}", exc_info=True)
        raise

# Test rapide si le script est exécuté directement
if __name__ == "__main__":
    test_network = "192.168.1.0/24"
    logger.info("Exécution du test de découverte réseau")
    try:
        results = discover_network(test_network)
        for r in results:
            print(f"IP: {r['ip']}, Hostname: {r['hostname']}, État: {r['state']}")
        logger.info("Test terminé avec succès")
    except Exception as e:
        logger.error(f"Erreur lors du test: {e}", exc_info=True)
