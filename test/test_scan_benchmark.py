import pytest
from services.port_scanner import scan_ports

@pytest.mark.benchmark(group="portscan")
def test_scan_small_range(benchmark):
    # On mesure scan_ports sur un petit réseau fictif
    result = benchmark(lambda: scan_ports("127.0.0.1", "1-100"))
    # Optionnel : on peut valider des invariants
    assert isinstance(result, list)
