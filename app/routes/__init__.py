from .discovery_routes import discovery_bp
from .enumeration_routes import enumeration_bp
from .exploit import exploit_bp
from .forensics_routes import forensics_bp
from .hydra_routes import hydra_bp
from .malware_routes import malware_bp
from .scan import scan_bp
from .sniffer import sniffer_bp
from .timeline_routes import timeline_bp
from .vuln_routes import vuln_bp

blueprints = [
    discovery_bp,
    enumeration_bp,
    exploit_bp,
    forensics_bp,
    hydra_bp,
    malware_bp,
    scan_bp,
    sniffer_bp,
    timeline_bp,
    vuln_bp
]
