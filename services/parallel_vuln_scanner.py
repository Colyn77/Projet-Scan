import nmap
import asyncio
import threading
import datetime
import os
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from queue import Queue
import uuid
from utils.logger import get_logger
from services.reporting_generator import generate_vuln_report

# Configuration du logger
logger = get_logger('parallel_vuln_scanner')

# Répertoires pour stocker les rapports et résultats
CAPTURE_DIR = "vuln_reports"
JOBS_RESULTS_DIR = "scan_results"
os.makedirs(CAPTURE_DIR, exist_ok=True)
os.makedirs(JOBS_RESULTS_DIR, exist_ok=True)

@dataclass
class ScanJob:
    """Représente un travail de scan"""
    job_id: str
    target: str
    ports: str
    status: str = "pending"  # pending, running, completed, failed
    start_time: Optional[datetime.datetime] = None
    end_time: Optional[datetime.datetime] = None
    progress: int = 0
    results: Optional[Dict] = None
    error: Optional[str] = None
    html_report: Optional[str] = None
    pdf_report: Optional[str] = None

class ParallelVulnScanner:
    """Gestionnaire de scans de vulnérabilités parallèles"""
    
    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.jobs: Dict[str, ScanJob] = {}
        self.progress_callbacks: Dict[str, callable] = {}
        
    def create_scan_job(self, targets: List[str], ports: str = "21,22,23,25,80,110,139,143,443,445,3389") -> List[str]:
        """Crée des jobs de scan pour plusieurs cibles"""
        job_ids = []
        
        for target in targets:
            job_id = str(uuid.uuid4())
            job = ScanJob(
                job_id=job_id,
                target=target.strip(),
                ports=ports
            )
            self.jobs[job_id] = job
            job_ids.append(job_id)
            logger.info(f"Job créé: {job_id} pour {target}")
            
        return job_ids
    
    def create_port_range_jobs(self, target: str, port_ranges: List[str]) -> List[str]:
        """Crée des jobs pour scanner différentes plages de ports sur la même cible"""
        job_ids = []
        
        for port_range in port_ranges:
            job_id = str(uuid.uuid4())
            job = ScanJob(
                job_id=job_id,
                target=target,
                ports=port_range.strip()
            )
            self.jobs[job_id] = job
            job_ids.append(job_id)
            logger.info(f"Job créé: {job_id} pour {target} ports {port_range}")
            
        return job_ids
    
    def start_parallel_scan(self, job_ids: List[str]) -> str:
        """Lance les scans en parallèle"""
        batch_id = str(uuid.uuid4())
        logger.info(f"Démarrage du batch {batch_id} avec {len(job_ids)} jobs")
        
        # Soumettre tous les jobs à l'executor
        futures = {}
        for job_id in job_ids:
            if job_id in self.jobs:
                future = self.executor.submit(self._execute_single_scan, job_id)
                futures[future] = job_id
                self.jobs[job_id].status = "running"
                self.jobs[job_id].start_time = datetime.datetime.now()
        
        # Optionnellement, on peut créer un thread pour surveiller les résultats
        monitoring_thread = threading.Thread(
            target=self._monitor_batch, 
            args=(futures, batch_id)
        )
        monitoring_thread.daemon = True
        monitoring_thread.start()
        
        return batch_id
    
    def _execute_single_scan(self, job_id: str) -> Dict[str, Any]:
        """Exécute un scan individuel"""
        job = self.jobs[job_id]
        logger.info(f"Début du scan pour job {job_id}: {job.target}")
        
        try:
            job.progress = 10
            scanner = nmap.PortScanner()
            
            # Test de disponibilité de l'hôte
            job.progress = 20
            scanner.scan(hosts=job.target, arguments="-sn")
            if job.target not in scanner.all_hosts():
                raise Exception(f"L'hôte {job.target} n'est pas accessible")
            
            # Scan des ports avec scripts de vulnérabilités
            job.progress = 40
            arguments = f"--script vuln -p {job.ports}"
            scanner.scan(hosts=job.target, arguments=arguments)
            
            # Traitement des résultats
            job.progress = 70
            result = self._process_scan_results(scanner, job.target, job.ports)
            
            # Génération des rapports individuels
            job.progress = 85
            self._generate_job_reports(job_id, result)
            
            # Sauvegarde des résultats
            job.progress = 95
            self._save_job_results(job_id, result)
            
            # Finalisation
            job.progress = 100
            job.status = "completed"
            job.end_time = datetime.datetime.now()
            job.results = result
            
            logger.info(f"Scan terminé pour job {job_id}: {len(result.get('vulnerabilities', []))} vulnérabilités trouvées")
            return result
            
        except Exception as e:
            job.status = "failed"
            job.error = str(e)
            job.end_time = datetime.datetime.now()
            logger.error(f"Erreur dans le job {job_id}: {str(e)}")
            return {"error": str(e)}
    
    def _process_scan_results(self, scanner: nmap.PortScanner, target: str, ports: str) -> Dict[str, Any]:
        """Traite les résultats du scan"""
        result = {
            "target": target,
            "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "host_status": "up" if scanner[target].state() == "up" else "down",
            "vulnerabilities": [],
            "command_line": f"nmap --script vuln -p {ports} {target}",
            "ports_scanned": ports
        }
        
        # Extraction des vulnérabilités
        for proto in scanner[target].all_protocols():
            ports_list = scanner[target][proto].keys()
            for port in ports_list:
                port_info = scanner[target][proto][port]
                if 'script' in port_info:
                    for script_name, script_output in port_info['script'].items():
                        if "vuln" in script_name or "VULNERABLE" in str(script_output).upper():
                            vuln_data = {
                                "port": port,
                                "protocol": proto,
                                "service": port_info.get('name', 'unknown'),
                                "state": port_info.get('state', 'unknown'),
                                "vulnerability": script_name,
                                "details": script_output
                            }
                            result["vulnerabilities"].append(vuln_data)
        
        return result
    
    def _generate_job_reports(self, job_id: str, results: Dict[str, Any]):
        """Génère les rapports HTML et PDF pour un job individuel"""
        job = self.jobs[job_id]
        
        try:
            # Générer le rapport HTML
            html_report = generate_vuln_report(results, for_download=True, format="html")
            job.html_report = html_report
            logger.info(f"Rapport HTML généré pour job {job_id}: {html_report}")
            
            # Générer le rapport PDF
            pdf_report = generate_vuln_report(results, for_download=True, format="pdf")
            job.pdf_report = pdf_report
            logger.info(f"Rapport PDF généré pour job {job_id}: {pdf_report}")
            
            # Ajouter les chemins des rapports aux résultats
            results["html_report"] = html_report
            results["pdf_report"] = pdf_report
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération des rapports pour job {job_id}: {e}")
            job.html_report = None
            job.pdf_report = None
    
    def _save_job_results(self, job_id: str, results: Dict[str, Any]):
        """Sauvegarde les résultats d'un job dans un fichier JSON"""
        try:
            results_file = os.path.join(JOBS_RESULTS_DIR, f"{job_id}.json")
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            logger.info(f"Résultats sauvegardés pour job {job_id}: {results_file}")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des résultats pour job {job_id}: {e}")
    
    def load_job_results(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Charge les résultats d'un job depuis le fichier JSON"""
        try:
            results_file = os.path.join(JOBS_RESULTS_DIR, f"{job_id}.json")
            if os.path.exists(results_file):
                with open(results_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return None
        except Exception as e:
            logger.error(f"Erreur lors du chargement des résultats pour job {job_id}: {e}")
            return None
    
    def _monitor_batch(self, futures: Dict, batch_id: str):
        """Surveille l'exécution d'un batch de scans"""
        logger.info(f"Surveillance du batch {batch_id}")
        completed_jobs = 0
        total_jobs = len(futures)
        
        for future in as_completed(futures):
            job_id = futures[future]
            completed_jobs += 1
            logger.info(f"Job {job_id} terminé ({completed_jobs}/{total_jobs})")
            
            # Callback de progression si défini
            if batch_id in self.progress_callbacks:
                self.progress_callbacks[batch_id](completed_jobs, total_jobs)
        
        logger.info(f"Batch {batch_id} terminé: {completed_jobs} jobs")
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Récupère le statut d'un job"""
        if job_id not in self.jobs:
            return None
            
        job = self.jobs[job_id]
        status = {
            "job_id": job.job_id,
            "target": job.target,
            "ports": job.ports,
            "status": job.status,
            "progress": job.progress,
            "start_time": job.start_time.isoformat() if job.start_time else None,
            "end_time": job.end_time.isoformat() if job.end_time else None,
            "results": job.results,
            "error": job.error,
            "duration": (job.end_time - job.start_time).total_seconds() if job.start_time and job.end_time else None,
            "html_report": job.html_report,
            "pdf_report": job.pdf_report
        }
        
        # Si le job est terminé mais qu'on n'a pas les résultats en mémoire, les charger
        if job.status == "completed" and job.results is None:
            loaded_results = self.load_job_results(job_id)
            if loaded_results:
                job.results = loaded_results
                status["results"] = loaded_results
        
        return status
    
    def get_batch_status(self, job_ids: List[str]) -> Dict[str, Any]:
        """Récupère le statut d'un batch de jobs"""
        batch_status = {
            "total_jobs": len(job_ids),
            "completed": 0,
            "running": 0,
            "failed": 0,
            "pending": 0,
            "jobs": []
        }
        
        for job_id in job_ids:
            job_status = self.get_job_status(job_id)
            if job_status:
                batch_status["jobs"].append(job_status)
                status = job_status["status"]
                if status == "completed":
                    batch_status["completed"] += 1
                elif status == "running":
                    batch_status["running"] += 1
                elif status == "failed":
                    batch_status["failed"] += 1
                elif status == "pending":
                    batch_status["pending"] += 1
        
        batch_status["progress"] = (batch_status["completed"] / batch_status["total_jobs"]) * 100 if batch_status["total_jobs"] > 0 else 0
        
        return batch_status
    
    def cleanup_old_jobs(self, max_age_hours: int = 24):
        """Nettoie les anciens jobs"""
        cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=max_age_hours)
        jobs_to_remove = []
        
        for job_id, job in self.jobs.items():
            if job.end_time and job.end_time < cutoff_time:
                jobs_to_remove.append(job_id)
                
                # Supprimer aussi les fichiers de résultats
                try:
                    results_file = os.path.join(JOBS_RESULTS_DIR, f"{job_id}.json")
                    if os.path.exists(results_file):
                        os.remove(results_file)
                except Exception as e:
                    logger.error(f"Erreur lors de la suppression du fichier de résultats: {e}")
        
        for job_id in jobs_to_remove:
            del self.jobs[job_id]
            logger.info(f"Job {job_id} supprimé (trop ancien)")
    
    def cancel_job(self, job_id: str) -> bool:
        """Annule un job (si possible)"""
        if job_id in self.jobs and self.jobs[job_id].status in ["pending", "running"]:
            self.jobs[job_id].status = "cancelled"
            self.jobs[job_id].end_time = datetime.datetime.now()
            logger.info(f"Job {job_id} annulé")
            return True
        return False

# Instance globale du scanner parallèle
parallel_scanner = ParallelVulnScanner(max_workers=3)

def parse_targets(targets_input: str) -> List[str]:
    """Parse l'entrée des cibles multiples"""
    targets = []
    
    # Séparer par virgules, points-virgules ou nouvelles lignes
    raw_targets = targets_input.replace(';', ',').replace('\n', ',').split(',')
    
    for target in raw_targets:
        target = target.strip()
        if target:
            # Gérer les plages IP (ex: 192.168.1.1-192.168.1.10)
            if '-' in target and '.' in target:
                parts = target.split('-')
                if len(parts) == 2:
                    try:
                        start_ip = parts[0].strip()
                        end_ip = parts[1].strip()
                        
                        # Si c'est juste le dernier octet
                        if '.' not in end_ip:
                            base_ip = '.'.join(start_ip.split('.')[:-1])
                            start_last = int(start_ip.split('.')[-1])
                            end_last = int(end_ip)
                            
                            for i in range(start_last, end_last + 1):
                                targets.append(f"{base_ip}.{i}")
                        else:
                            # Plage complète - implémentation basique
                            targets.extend([start_ip, end_ip])
                    except:
                        targets.append(target)
                else:
                    targets.append(target)
            else:
                targets.append(target)
    
    return list(set(targets))  # Supprimer les doublons

def parse_port_ranges(ports_input: str) -> List[str]:
    """Parse l'entrée des plages de ports"""
    port_ranges = []
    
    # Séparer par points-virgules pour créer des groupes
    raw_ranges = ports_input.split(';')
    
    for port_range in raw_ranges:
        port_range = port_range.strip()
        if port_range:
            port_ranges.append(port_range)
    
    return port_ranges if len(port_ranges) > 1 else [ports_input]
