// Script JavaScript pour l'interface de scan de vulnérabilités
document.addEventListener('DOMContentLoaded', function() {
    // Éléments du formulaire
    const form = document.getElementById('vuln-form');
    const targetInput = document.getElementById('target');
    const portsInput = document.getElementById('ports');
    const portCategorySelect = document.getElementById('port-category');
    const startBtn = document.getElementById('start-vuln-btn');
    
    // Cache pour les catégories de ports
    let portCategories = {};
    
    // Charger les catégories de ports au démarrage
    loadPortCategories();
    
    function loadPortCategories() {
        fetch('/api/vuln/ports')
        .then(response => response.json())
        .then(data => {
            portCategories = data;
            console.log('Catégories de ports chargées:', portCategories);
        })
        .catch(error => {
            console.error('Erreur lors du chargement des catégories de ports:', error);
        });
    }
    
    // Gestionnaire pour le changement de catégorie de ports
    if (portCategorySelect) {
        portCategorySelect.addEventListener('change', function() {
            const category = this.value;
            if (category === 'custom') {
                portsInput.value = '';
                portsInput.focus();
            } else if (portCategories[category]) {
                portsInput.value = portCategories[category];
            }
        });
    }
    
    // Validation en temps réel de l'entrée cible
    if (targetInput) {
        targetInput.addEventListener('input', function() {
            validateTarget(this.value);
        });
    }
    
    // Validation en temps réel des ports
    if (portsInput) {
        portsInput.addEventListener('input', function() {
            validatePorts(this.value);
        });
    }
    
    function validateTarget(target) {
        const targetTrimmed = target.trim();
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
        
        // Supprimer les classes de validation précédentes
        targetInput.classList.remove('valid', 'invalid');
        
        if (targetTrimmed === '') {
            return false;
        }
        
        const isValid = ipRegex.test(targetTrimmed) || domainRegex.test(targetTrimmed);
        
        if (isValid) {
            targetInput.classList.add('valid');
            return true;
        } else {
            targetInput.classList.add('invalid');
            return false;
        }
    }
    
    function validatePorts(ports) {
        const portsTrimmed = ports.trim();
        // Regex pour valider les formats de ports: 80, 80-90, 80,443,8080
        const portsRegex = /^(\d+(-\d+)?)(,\s*\d+(-\d+)?)*$/;
        
        // Supprimer les classes de validation précédentes
        portsInput.classList.remove('valid', 'invalid');
        
        if (portsTrimmed === '') {
            return false;
        }
        
        const isValid = portsRegex.test(portsTrimmed);
        
        if (isValid) {
            portsInput.classList.add('valid');
            return true;
        } else {
            portsInput.classList.add('invalid');
            return false;
        }
    }
    
    // Soumission du formulaire
    if (form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const target = targetInput.value.trim();
            const ports = portsInput.value.trim();
            
            // Validation finale
            if (!target) {
                showAlert('Veuillez spécifier une cible', 'error');
                targetInput.focus();
                return;
            }
            
            if (!validateTarget(target)) {
                showAlert('Format de cible invalide (IP ou nom de domaine attendu)', 'error');
                targetInput.focus();
                return;
            }
            
            if (!ports) {
                showAlert('Veuillez spécifier des ports à scanner', 'error');
                portsInput.focus();
                return;
            }
            
            if (!validatePorts(ports)) {
                showAlert('Format de ports invalide', 'error');
                portsInput.focus();
                return;
            }
            
            // Lancer le scan
            startScan(target, ports);
        });
    }
    
    function startScan(target, ports) {
        // Désactiver le bouton et changer son texte
        startBtn.disabled = true;
        const originalText = startBtn.innerHTML;
        startBtn.innerHTML = '<i class="spinner"></i> Scan en cours...';
        
        // Créer l'indicateur de chargement
        const loadingDiv = createLoadingIndicator();
        form.parentNode.insertBefore(loadingDiv, form.nextSibling);
        
        // Préparer les données
        const formData = new FormData();
        formData.append('target', target);
        formData.append('ports', ports);
        
        // Envoyer la requête
        fetch('/api/vuln/nmap', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (response.headers.get('content-type')?.includes('application/json')) {
                return response.json();
            } else {
                // Si c'est du HTML, rediriger vers la page de résultats
                return response.text().then(html => {
                    document.open();
                    document.write(html);
                    document.close();
                    return null;
                });
            }
        })
        .then(data => {
            if (data === null) {
                // Redirection HTML effectuée
                return;
            }
            
            if (data.error) {
                throw new Error(data.error);
            }
            
            // Afficher les résultats
            displayResults(data);
        })
        .catch(error => {
            console.error('Erreur lors du scan:', error);
            showAlert('Erreur lors du scan: ' + error.message, 'error');
        })
        .finally(() => {
            // Réactiver le bouton
            startBtn.disabled = false;
            startBtn.innerHTML = originalText;
            
            // Supprimer l'indicateur de chargement
            if (loadingDiv && loadingDiv.parentNode) {
                loadingDiv.parentNode.removeChild(loadingDiv);
            }
        });
    }
    
    function createLoadingIndicator() {
        const div = document.createElement('div');
        div.className = 'loading-indicator';
        div.innerHTML = `
            <div style="
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                text-align: center;
                margin: 20px 0;
            ">
                <div style="
                    display: inline-block;
                    width: 40px;
                    height: 40px;
                    border: 4px solid #f3f3f3;
                    border-top: 4px solid #2c3e50;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                    margin-bottom: 15px;
                "></div>
                <div>
                    <strong>Scan en cours...</strong>
                </div>
                <div style="color: #666; margin-top: 5px;">
                    Recherche de vulnérabilités sur ${targetInput.value}:${portsInput.value}
                </div>
                <div style="margin-top: 15px;">
                    <small>Cela peut prendre plusieurs minutes selon le nombre de ports</small>
                </div>
            </div>
        `;
        
        return div;
    }
    
    function displayResults(data) {
        // Créer une section de résultats
        const resultsDiv = document.createElement('div');
        resultsDiv.className = 'scan-results';
        resultsDiv.innerHTML = generateResultsHTML(data);
        
        // Insérer après le formulaire
        form.parentNode.insertBefore(resultsDiv, form.nextSibling);
        
        // Scroll vers les résultats
        resultsDiv.scrollIntoView({ behavior: 'smooth' });
    }
    
    function generateResultsHTML(data) {
        const vulnCount = data.vulnerabilities ? data.vulnerabilities.length : 0;
        const hasVulns = vulnCount > 0;
        
        let html = `
        <div style="
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin: 20px 0;
        ">
            <h2 style="color: #2c3e50; margin-bottom: 20px;">
                <i class="bi bi-clipboard-data"></i> Résultats du Scan
            </h2>
            
            <div style="
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-bottom: 25px;
            ">
                <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #2c3e50;">${data.target}</div>
                    <div style="color: #666; font-size: 0.9rem;">Cible</div>
                </div>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: ${data.host_status === 'up' ? '#28a745' : '#dc3545'};">
                        ${data.host_status === 'up' ? 'En ligne' : 'Hors ligne'}
                    </div>
                    <div style="color: #666; font-size: 0.9rem;">Statut</div>
                </div>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: ${hasVulns ? '#dc3545' : '#28a745'};">
                        ${vulnCount}
                    </div>
                    <div style="color: #666; font-size: 0.9rem;">Vulnérabilités</div>
                </div>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #2c3e50;">${data.scan_time}</div>
                    <div style="color: #666; font-size: 0.9rem;">Heure du scan</div>
                </div>
            </div>
        `;
        
        if (hasVulns) {
            html += `
            <div style="margin-bottom: 25px;">
                <h3 style="color: #dc3545; margin-bottom: 15px;">
                    <i class="bi bi-exclamation-triangle"></i> Vulnérabilités Détectées
                </h3>
                <div style="background: #fff8f8; border: 1px solid #f5c6cb; border-radius: 6px; padding: 15px;">
                    <div style="color: #721c24; font-weight: bold; margin-bottom: 10px;">
                        ⚠️ ${vulnCount} vulnérabilité(s) trouvée(s) sur cette cible
                    </div>
                    <div style="color: #856404; font-size: 0.9rem;">
                        Consultez les détails ci-dessous et prenez les mesures appropriées pour sécuriser votre système.
                    </div>
                </div>
            </div>
            
            <div style="margin-bottom: 25px;">
                <h4>Détails des Vulnérabilités</h4>
                ${data.vulnerabilities.map((vuln, index) => `
                    <div style="
                        border: 1px solid #dee2e6;
                        border-radius: 6px;
                        margin-bottom: 15px;
                        overflow: hidden;
                        ${getSeverityStyle(vuln.vulnerability)}
                    ">
                        <div style="background: #f8f9fa; padding: 15px; border-bottom: 1px solid #dee2e6;">
                            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                                <div>
                                    <strong style="color: #2c3e50;">${vuln.vulnerability}</strong>
                                    <div style="color: #666; font-size: 0.9rem; margin-top: 5px;">
                                        Port ${vuln.port}/${vuln.protocol} - ${vuln.service} (${vuln.state})
                                    </div>
                                </div>
                                <span style="
                                    background: #dc3545;
                                    color: white;
                                    padding: 4px 8px;
                                    border-radius: 4px;
                                    font-size: 0.8rem;
                                    font-weight: bold;
                                ">VULNÉRABLE</span>
                            </div>
                        </div>
                        <div style="padding: 15px;">
                            <details>
                                <summary style="cursor: pointer; font-weight: bold; margin-bottom: 10px;">
                                    Voir les détails techniques
                                </summary>
                                <pre style="
                                    background: #f8f9fa;
                                    padding: 10px;
                                    border-radius: 4px;
                                    font-size: 0.8rem;
                                    overflow-x: auto;
                                    white-space: pre-wrap;
                                    color: #495057;
                                ">${vuln.details || 'Aucun détail disponible'}</pre>
                            </details>
                        </div>
                    </div>
                `).join('')}
            </div>
            `;
        } else {
            html += `
            <div style="
                background: #d4edda;
                border: 1px solid #c3e6cb;
                border-radius: 6px;
                padding: 20px;
                text-align: center;
                margin-bottom: 25px;
            ">
                <div style="color: #155724; font-size: 1.2rem; font-weight: bold; margin-bottom: 10px;">
                    <i class="bi bi-shield-check" style="font-size: 2rem; display: block; margin-bottom: 10px;"></i>
                    Aucune vulnérabilité détectée
                </div>
                <div style="color: #155724;">
                    Le scan n'a pas détecté de vulnérabilités connues sur les ports analysés.
                    <br>Continuez à maintenir vos systèmes à jour pour garantir leur sécurité.
                </div>
            </div>
            `;
        }
        
        // Ajouter les liens de téléchargement et actions
        html += `
            <div style="
                background: #f8f9fa;
                padding: 20px;
                border-radius: 6px;
                border-top: 3px solid #2c3e50;
            ">
                <h4 style="margin-bottom: 15px;">Actions</h4>
                <div style="display: flex; gap: 15px; flex-wrap: wrap;">
                    ${data.html_report ? `
                    <a href="/api/vuln/download_report?filename=${encodeURIComponent(data.html_report.split('/').pop())}&format=html" 
                       style="
                           background: #2c3e50;
                           color: white;
                           padding: 10px 15px;
                           border-radius: 4px;
                           text-decoration: none;
                           font-weight: bold;
                           display: inline-flex;
                           align-items: center;
                           gap: 5px;
                       ">
                        <i class="bi bi-download"></i> Télécharger HTML
                    </a>
                    ` : ''}
                    
                    ${data.pdf_report ? `
                    <a href="/api/vuln/download_report?filename=${encodeURIComponent(data.pdf_report.split('/').pop())}&format=pdf" 
                       style="
                           background: #dc3545;
                           color: white;
                           padding: 10px 15px;
                           border-radius: 4px;
                           text-decoration: none;
                           font-weight: bold;
                           display: inline-flex;
                           align-items: center;
                           gap: 5px;
                       ">
                        <i class="bi bi-file-pdf"></i> Télécharger PDF
                    </a>
                    ` : ''}
                    
                    <button onclick="copyResultsToClipboard()" style="
                        background: #6c757d;
                        color: white;
                        padding: 10px 15px;
                        border: none;
                        border-radius: 4px;
                        font-weight: bold;
                        cursor: pointer;
                        display: inline-flex;
                        align-items: center;
                        gap: 5px;
                    ">
                        <i class="bi bi-clipboard"></i> Copier les résultats
                    </button>
                    
                    <button onclick="newScan()" style="
                        background: #28a745;
                        color: white;
                        padding: 10px 15px;
                        border: none;
                        border-radius: 4px;
                        font-weight: bold;
                        cursor: pointer;
                        display: inline-flex;
                        align-items: center;
                        gap: 5px;
                    ">
                        <i class="bi bi-arrow-repeat"></i> Nouveau scan
                    </button>
                </div>
            </div>
            
            <div style="margin-top: 20px; padding: 15px; background: #e9ecef; border-radius: 6px;">
                <details>
                    <summary style="cursor: pointer; font-weight: bold;">Commande utilisée</summary>
                    <code style="
                        display: block;
                        margin-top: 10px;
                        padding: 10px;
                        background: #f8f9fa;
                        border-radius: 4px;
                        font-family: monospace;
                    ">${data.command_line || 'N/A'}</code>
                </details>
            </div>
        </div>
        `;
        
        return html;
    }
    
    function getSeverityStyle(vulnName) {
        const vulnLower = vulnName.toLowerCase();
        if (vulnLower.includes('critical') || vulnLower.includes('rce') || vulnLower.includes('remote code')) {
            return 'border-left: 5px solid #dc3545;';
        } else if (vulnLower.includes('high') || vulnLower.includes('exploit')) {
            return 'border-left: 5px solid #fd7e14;';
        } else if (vulnLower.includes('medium') || vulnLower.includes('info')) {
            return 'border-left: 5px solid #ffc107;';
        }
        return 'border-left: 5px solid #28a745;';
    }
    
    function showAlert(message, type = 'info') {
        // Supprimer les alertes existantes
        const existingAlerts = document.querySelectorAll('.custom-alert');
        existingAlerts.forEach(alert => alert.remove());
        
        // Créer l'alerte
        const alertDiv = document.createElement('div');
        alertDiv.className = 'custom-alert';
        
        const bgColor = type === 'error' ? '#f8d7da' : (type === 'success' ? '#d4edda' : '#d1ecf1');
        const textColor = type === 'error' ? '#721c24' : (type === 'success' ? '#155724' : '#0c5460');
        const borderColor = type === 'error' ? '#f5c6cb' : (type === 'success' ? '#c3e6cb' : '#bee5eb');
        
        alertDiv.style.cssText = `
            background: ${bgColor};
            color: ${textColor};
            border: 1px solid ${borderColor};
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
            display: flex;
            align-items: center;
            gap: 10px;
            animation: slideIn 0.3s ease-out;
        `;
        
        const icon = type === 'error' ? 'bi-exclamation-triangle' : (type === 'success' ? 'bi-check-circle' : 'bi-info-circle');
        
        alertDiv.innerHTML = `
            <i class="bi ${icon}"></i>
            <span>${message}</span>
            <button onclick="this.parentElement.remove()" style="
                background: none;
                border: none;
                color: ${textColor};
                font-size: 1.2rem;
                cursor: pointer;
                margin-left: auto;
                padding: 0;
                width: 20px;
                height: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
            ">&times;</button>
        `;
        
        // Insérer avant le formulaire
        form.parentNode.insertBefore(alertDiv, form);
        
        // Auto-suppression après 5 secondes
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
    
    // Ajouter les styles CSS dynamiquement
    const style = document.createElement('style');
    style.textContent = `
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .form-control.valid {
            border-color: #28a745;
            box-shadow: 0 0 0 2px rgba(40, 167, 69, 0.2);
        }
        
        .form-control.invalid {
            border-color: #dc3545;
            box-shadow: 0 0 0 2px rgba(220, 53, 69, 0.2);
        }
        
        .spinner {
            display: inline-block;
            width: 12px;
            height: 12px;
            border: 2px solid #ffffff;
            border-radius: 50%;
            border-top-color: transparent;
            animation: spin 1s ease-in-out infinite;
        }
    `;
    document.head.appendChild(style);
});

// Fonctions globales pour les actions des résultats
function copyResultsToClipboard() {
    const resultsDiv = document.querySelector('.scan-results');
    if (resultsDiv) {
        // Extraire le texte des résultats
        const textContent = resultsDiv.innerText;
        
        navigator.clipboard.writeText(textContent).then(function() {
            // Créer une notification temporaire
            const notification = document.createElement('div');
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                background: #28a745;
                color: white;
                padding: 10px 20px;
                border-radius: 6px;
                z-index: 1000;
                animation: slideIn 0.3s ease-out;
            `;
            notification.innerHTML = '<i class="bi bi-check"></i> Résultats copiés dans le presse-papiers';
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 3000);
        }).catch(function(err) {
            console.error('Erreur lors de la copie:', err);
            alert('Impossible de copier dans le presse-papiers');
        });
    }
}

function newScan() {
    // Supprimer les résultats existants
    const resultsDiv = document.querySelector('.scan-results');
    if (resultsDiv) {
        resultsDiv.remove();
    }
    
    // Remettre le focus sur le champ cible
    const targetInput = document.getElementById('target');
    if (targetInput) {
        targetInput.focus();
        targetInput.select();
    }
    
    // Scroll vers le haut
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Fonction pour formater les données d'export
function exportScanData(data, format = 'json') {
    const exportData = {
        scan_info: {
            target: data.target,
            ports: data.ports || 'N/A',
            scan_time: data.scan_time,
            host_status: data.host_status,
            command_line: data.command_line
        },
        vulnerabilities: data.vulnerabilities || [],
        summary: {
            total_vulnerabilities: data.vulnerabilities ? data.vulnerabilities.length : 0,
            scan_successful: !data.error
        }
    };
    
    if (format === 'json') {
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vuln_scan_${data.target}_${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } else if (format === 'csv') {
        // Export CSV des vulnérabilités
        if (exportData.vulnerabilities.length > 0) {
            const csvContent = [
                ['Port', 'Protocol', 'Service', 'State', 'Vulnerability', 'Details'],
                ...exportData.vulnerabilities.map(vuln => [
                    vuln.port,
                    vuln.protocol,
                    vuln.service,
                    vuln.state,
                    vuln.vulnerability,
                    (vuln.details || '').replace(/"/g, '""') // Échapper les guillemets
                ])
            ].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
            
            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vuln_scan_${data.target}_${new Date().toISOString().split('T')[0]}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } else {
            alert('Aucune vulnérabilité à exporter en CSV');
        }
    }
}
