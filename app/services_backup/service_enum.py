import nmap
from app.utils.logger import get_logger

# Configuration du logger
logger = get_logger('service_enum')

def enumerate_services(target, ports):
    """
    Enumère les services et affiche toutes les informations récupérées par Nmap.
    """
    logger.info(f"Démarrage de l'énumération des services sur {target}")
    logger.debug(f"Ports à énumérer: {ports}")
    
    try:
        nm = nmap.PortScanner()
        logger.info(f"Scan d'énumération sur {target} (ports : {ports})")

        # Ajout de l'option -sV pour la détection des versions
        logger.debug("Exécution du scan avec l'option -sV pour la détection des versions")
        nm.scan(hosts=target, ports=ports, arguments="-sV")

        services = []
        services_count = 0

        for host in nm.all_hosts():
            logger.debug(f"Énumération des services pour l'hôte: {host}")
            
            for proto in nm[host].all_protocols():
                logger.debug(f"Protocole: {proto}")
                
                for port in nm[host][proto]:
                    port_data = nm[host][proto][port]
                    logger.debug(f"Données Nmap brutes pour le port {port}: {port_data}")

                    service = port_data.get("name", "Unknown")
                    version = port_data.get("version", "Non détectée")
                    product = port_data.get("product", "Inconnu")
                    extrainfo = port_data.get("extrainfo", "")

                    service_info = f"Port {port} : {service} (Produit : {product}, Version : {version}) {extrainfo}"
                    services.append(service_info)
                    services_count += 1
                    
                    logger.info(f"Service identifié: {service_info}")

        logger.info(f"Énumération terminée: {services_count} services identifiés")
        return services
        
    except Exception as e:
        logger.error(f"Erreur lors de l'énumération des services: {e}", exc_info=True)
        raise

# Test rapide si le script est exécuté directement
if __name__ == "__main__":
    logger.info("Exécution du test d'énumération des services")
    target = input("Entrez l'adresse IP cible : ")
    ports = input("Entrez les ports à scanner (ex: 22,80,443) : ")
    
    try:
        results = enumerate_services(target, ports)
        for service in results:
            print(service)
        logger.info("Test terminé avec succès")
    except Exception as e:
        logger.error(f"Erreur lors du test: {e}", exc_info=True)
