#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exporter Prometheus pour la Toolbox

- Se connecte à PostgreSQL (bdd scan_results)
- Toutes les SCRAPE_INTERVAL secondes, interroge la table logs pour calculer :
    • Nombre de logs par module sur la dernière minute
    • Nombre d’erreurs (niveau = ERROR) par module sur la dernière minute
    • Latence moyenne par module (si duration stockée dans métadonnées)
- Expose ces métriques sur /metrics au format Prometheus
"""

import time
import threading
import psycopg2
from prometheus_client import start_http_server, Gauge

# === CONFIG POSTGRESQL ===
DB_CONFIG = {
    "dbname":   "scan_results",
    "user":     "scan_user",
    "password": "colyn123",
    "host":     "localhost",
    "port":     "5432"
}

# === DÉFINITION DES MÉTRIQUES PROMETHEUS ===
gauge_logs_per_module = Gauge(
    'toolbox_logs_per_module',
    'Nombre de logs générés par module sur la dernière minute',
    ['module']
)

gauge_errors_per_module = Gauge(
    'toolbox_errors_per_module',
    'Nombre de logs de niveau ERROR par module sur la dernière minute',
    ['module']
)

gauge_latency_per_module = Gauge(
    'toolbox_latency_per_module_seconds',
    'Latence moyenne (en secondes) des tâches par module, calculée sur la dernière minute',
    ['module']
)

SCRAPE_INTERVAL = 30  # secondes

def fetch_and_update_metrics():
    """
    Exécuté périodiquement : interroge la table 'logs' et met à jour les Gauge Prometheus.
    """
    while True:
        print("[Exporter.debug] fetch_and_update_metrics tick")
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            cursor = conn.cursor()

            # Récupérer la liste des modules présents dans la dernière minute
            cursor.execute("""
                SELECT source
                FROM logs
                WHERE timestamp >= NOW() - INTERVAL '1 minute'
                GROUP BY source;
            """)
            modules = [row[0] for row in cursor.fetchall()]

            for mod in modules:
                # a) Nombre total de logs pour ce module sur la dernière minute
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM logs
                    WHERE source = %s
                      AND timestamp >= NOW() - INTERVAL '1 minute';
                """, (mod,))
                total = cursor.fetchone()[0] or 0

                # b) Nombre d'erreurs (niveau = 'ERROR') sur la dernière minute
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM logs
                    WHERE source = %s
                      AND niveau = 'ERROR'
                      AND timestamp >= NOW() - INTERVAL '1 minute';
                """, (mod,))
                errs = cursor.fetchone()[0] or 0

                # c) Latence moyenne si 'duration' existe dans métadonnées
                cursor.execute("""
                    SELECT AVG((métadonnées->>'duration')::numeric)
                    FROM logs
                    WHERE source = %s
                      AND (métadonnées ? 'duration')
                      AND timestamp >= NOW() - INTERVAL '1 minute';
                """, (mod,))
                avg_latency = cursor.fetchone()[0]
                avg_latency = float(avg_latency) if avg_latency is not None else 0.0

                # Mise à jour des métriques Prometheus
                gauge_logs_per_module.labels(module=mod).set(total)
                gauge_errors_per_module.labels(module=mod).set(errs)
                gauge_latency_per_module.labels(module=mod).set(avg_latency)

                print(f"[Exporter.debug] module={mod} total={total} errs={errs} avg_latency={avg_latency}")

            cursor.close()
            conn.close()

        except Exception as e:
            print(f"[Exporter.debug] ERREUR SQL : {e}")

        time.sleep(SCRAPE_INTERVAL)


def main():
    # Démarrer le serveur HTTP de Prometheus sur le port 8000
    start_http_server(8000)
    print("[Exporter] Serveur HTTP démarré sur le port 8000")

    # Lancer la récupération des metrics dans un thread dédié
    thread = threading.Thread(target=fetch_and_update_metrics, daemon=True)
    thread.start()

    # Bloquer le thread principal
    thread.join()


if __name__ == "__main__":
    main()
