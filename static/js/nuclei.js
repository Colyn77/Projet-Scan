// Variables globales
let currentResults = null;

// Fonction de debug pour les requêtes
async function debugFetch(url, options = {}) {
    console.log('=== DEBUG FETCH ===');
    console.log('URL:', url);
    console.log('Options:', options);
    console.log('Body:', options.body);
    
    try {
        const response = await fetch(url, options);
        console.log('Response status:', response.status);
        console.log('Response headers:', response.headers);
        
        // Lire le contenu de la réponse
        const responseText = await response.text();
        console.log('Response text:', responseText.substring(0, 500));
        
        // Essayer de parser en JSON
        try {
            const jsonData = JSON.parse(responseText);
            console.log('Parsed JSON:', jsonData);
            return { 
                ok: response.ok, 
                status: response.status, 
                json: () => Promise.resolve(jsonData),
                text: () => Promise.resolve(responseText)
            };
        } catch (jsonError) {
            console.error('JSON Parse Error:', jsonError);
            console.error('Response was not JSON:', responseText);
            throw new Error(`Réponse non-JSON reçue: ${responseText.substring(0, 100)}...`);
        }
    } catch (error) {
        console.error('Fetch Error:', error);
        throw error;
    }
}

// Fonction pour changer d'onglet
function switchTab(tabName) {
    console.log('Switching to tab:', tabName);
    
    // Masquer tous les contenus d'onglets
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    // Désactiver tous les onglets
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Activer l'onglet et le contenu sélectionnés
    document.getElementById(`tab-${tabName}`).classList.add('active');
    event.target.classList.add('active');
    
    // Charger l'historique si nécessaire
    if (tabName === 'history') {
        refreshHistory();
    }
}

// Fonction pour afficher/masquer les options avancées
function toggleAdvanced() {
    const advancedOptions = document.getElementById('advancedOptions');
    const isVisible = advancedOptions.style.display === 'block';
    advancedOptions.style.display = isVisible ? 'none' : 'block';
}

// Fonction pour collecter les valeurs des checkboxes
function getCheckedValues(name) {
    const checkboxes = document.querySelectorAll(`input[name="${name}"]:checked`);
    return Array.from(checkboxes).map(cb => cb.value);
}

// Gestion du formulaire de scan simple
document.getElementById('scanForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    console.log('=== FORM SUBMIT ===');
    
    const formData = new FormData(this);
    const url = formData.get('url');
    console.log('URL from form:', url);
    
    // Collecte des sévérités sélectionnées
    const severities = getCheckedValues('severity');
    const templates = getCheckedValues('templates');
    
    console.log('Severities:', severities);
    console.log('Templates:', templates);
    
    const data = {
        url: url,
        severity: severities.join(',') || 'medium,high,critical',
        templates: templates,
        timeout: parseInt(formData.get('timeout')) || 300,
        rate_limit: parseInt(formData.get('rate_limit')) || 150,
        user_agent: formData.get('user_agent') || ''
    };
    
    console.log('Data to send:', data);
    
    await performScan('/nuclei/scan', data);
});

// Gestion du formulaire de scan multiple
document.getElementById('batchScanForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    console.log('=== BATCH FORM SUBMIT ===');
    
    const formData = new FormData(this);
    const severities = getCheckedValues('batch_severity');
    
    const data = {
        urls: formData.get('urls'),
        severity: severities.join(',') || 'medium,high,critical',
        batch_size: parseInt(formData.get('batch_size')) || 10
    };
    
    console.log('Batch data to send:', data);
    
    await performScan('/nuclei/scan-multiple', data);
});

// Fonction principale pour effectuer un scan avec debug
async function performScan(endpoint, data) {
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    
    console.log('=== PERFORM SCAN ===');
    console.log('Endpoint:', endpoint);
    console.log('Data:', data);
    
    // Afficher le chargement
    loading.style.display = 'block';
    results.style.display = 'none';
    
    try {
        const response = await debugFetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        console.log('Scan result:', result);
        
        if (response.ok) {
            displayResults(result);
            showNotification('Scan terminé avec succès!', 'success');
        } else {
            throw new Error(result.error || 'Erreur inconnue');
        }
        
    } catch (error) {
        console.error('Scan error:', error);
        showNotification('Erreur: ' + error.message, 'error');
        
        // Afficher plus d'infos en mode debug
        if (error.message.includes('non-JSON')) {
            showNotification('Le serveur a renvoyé du HTML au lieu de JSON. Vérifiez les logs du serveur.', 'error');
        }
    } finally {
        loading.style.display = 'none';
    }
}

// Fonction pour afficher les notifications avec styles
function showNotification(message, type = 'info') {
    console.log('Notification:', type, message);
    
    // Créer la notification
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button onclick="this.parentElement.remove()">×</button>
    `;
    
    // Ajouter les styles si pas déjà présents
    if (!document.getElementById('notification-styles')) {
        const styles = document.createElement('style');
        styles.id = 'notification-styles';
        styles.textContent = `
            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 15px 20px;
                border-radius: 5px;
                color: white;
                z-index: 1000;
                display: flex;
                justify-content: space-between;
                align-items: center;
                min-width: 300px;
                animation: slideIn 0.3s ease;
                max-width: 500px;
                word-wrap: break-word;
            }
            .notification-info { background: #17a2b8; }
            .notification-success { background: #28a745; }
            .notification-warning { background: #ffc107; color: #212529; }
            .notification-error { background: #dc3545; }
            .notification button {
                background: none;
                border: none;
                color: inherit;
                font-size: 18px;
                cursor: pointer;
                margin-left: 15px;
                flex-shrink: 0;
            }
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        `;
        document.head.appendChild(styles);
    }
    
    document.body.appendChild(notification);
    
    // Auto-suppression après 8 secondes pour les erreurs, 5 pour le reste
    const timeout = type === 'error' ? 8000 : 5000;
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, timeout);
}

// Fonction pour afficher les résultats
function displayResults(data) {
    console.log('=== DISPLAY RESULTS ===');
    console.log('Data received:', data);
    
    const results = document.getElementById('results');
    const scanInfo = document.getElementById('scanInfo');
    const statsGrid = document.getElementById('statsGrid');
    const findingsContainer = document.getElementById('findingsContainer');
    
    currentResults = data;
    
    // Informations du scan
    if (data.scan_info) {
        const scanInfoHtml = data.scan_info.targets_count ? 
            `<p><strong>Cibles:</strong> ${data.scan_info.targets_count} URLs</p>` :
            `<p><strong>Cible:</strong> ${data.scan_info.target}</p>`;
        
        scanInfo.innerHTML = `
            ${scanInfoHtml}
            <p><strong>Date:</strong> ${data.scan_info.timestamp}</p>
            <p><strong>Sévérité:</strong> ${data.scan_info.severity}</p>
            <p><strong>Templates:</strong> ${Array.isArray(data.scan_info.templates_used) ? 
                data.scan_info.templates_used.join(', ') : 
                data.scan_info.templates_used}</p>
        `;
    }
    
    // Statistiques
    const stats = data.stats || {};
    statsGrid.innerHTML = `
        <div class="stat-card">
            <div class="stat-value">${stats.total || 0}</div>
            <div class="stat-label">Total</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.by_severity?.critical || 0}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.by_severity?.high || 0}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.by_severity?.medium || 0}</div>
            <div class="stat-label">Medium</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.by_severity?.low || 0}</div>
            <div class="stat-label">Low</div>
        </div>
    `;
    
    // Résultats détaillés
    displayFindings(data.findings || []);
    
    results.style.display = 'block';
    results.scrollIntoView({ behavior: 'smooth' });
}

// Reste des fonctions identiques mais avec plus de logs...
function displayFindings(findings) {
    console.log('Displaying findings:', findings.length);
    
    const container = document.getElementById('findingsContainer');
    
    if (!findings.length) {
        container.innerHTML = '<p>🎉 Aucune vulnérabilité trouvée!</p>';
        return;
    }
    
    const findingsHtml = findings.map((finding, index) => {
        const info = finding.info || {};
        const severity = info.severity || 'unknown';
        
        return `
            <div class="finding-item severity-${severity}">
                <div class="finding-header" onclick="toggleFinding(${index})">
                    <div>
                        <span class="finding-title">${info.name || 'Vulnérabilité inconnue'}</span>
                        <span class="severity-badge severity-${severity}">${severity.toUpperCase()}</span>
                    </div>
                    <span>▼</span>
                </div>
                <div class="finding-details" id="finding-${index}">
                    <p><strong>Description:</strong> ${info.description || 'Aucune description'}</p>
                    <p><strong>URL:</strong> ${finding.matched_at || finding.host || 'N/A'}</p>
                    ${info.reference ? `<p><strong>Référence:</strong> ${Array.isArray(info.reference) ? info.reference.join(', ') : info.reference}</p>` : ''}
                    ${finding.curl_command ? `<p><strong>Curl:</strong> <code>${finding.curl_command}</code></p>` : ''}
                    ${finding.response ? `<div><strong>Réponse:</strong><pre style="max-height: 200px; overflow-y: auto; background: #f8f9fa; padding: 10px; border-radius: 4px;">${finding.response.substring(0, 1000)}${finding.response.length > 1000 ? '...' : ''}</pre></div>` : ''}
                </div>
            </div>
        `;
    }).join('');
    
    container.innerHTML = `
        <div class="findings-container">
            <h4>🐛 Vulnérabilités détectées (${findings.length})</h4>
            ${findingsHtml}
        </div>
    `;
}

// Fonction pour afficher/masquer les détails d'une vulnérabilité
function toggleFinding(index) {
    const details = document.getElementById(`finding-${index}`);
    const isVisible = details.classList.contains('show');
    
    // Fermer tous les autres détails
    document.querySelectorAll('.finding-details').forEach(detail => {
        detail.classList.remove('show');
    });
    
    // Afficher ou masquer le détail sélectionné
    if (!isVisible) {
        details.classList.add('show');
    }
}

// Test de connexion au démarrage
document.addEventListener('DOMContentLoaded', async function() {
    console.log('=== PAGE LOADED ===');
    
    try {
        const response = await debugFetch('/nuclei/status');
        const status = await response.json();
        console.log('Nuclei status:', status);
        
        if (!status.available) {
            showNotification('Nuclei n\'est pas disponible sur ce système', 'warning');
        }
    } catch (error) {
        console.error('Status check failed:', error);
        showNotification('Impossible de vérifier le statut de Nuclei: ' + error.message, 'error');
    }
    
    refreshHistory();
});

// Fonctions utilitaires (versions simplifiées pour debug)
async function updateTemplates() {
    try {
        const response = await debugFetch('/nuclei/update-templates', {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showNotification('✅ Templates mis à jour avec succès!', 'success');
        } else {
            showNotification('❌ Erreur: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('❌ Erreur: ' + error.message, 'error');
    }
}

async function refreshHistory() {
    try {
        const response = await debugFetch('/nuclei/history');
        const data = await response.json();
        
        const tbody = document.getElementById('historyTable');
        
        if (data.history && data.history.length > 0) {
            tbody.innerHTML = data.history.map(scan => `
                <tr>
                    <td>${scan.timestamp.substring(0, 19).replace('T', ' ')}</td>
                    <td>${scan.filename}</td>
                    <td>${scan.findings_count}</td>
                    <td>${(scan.size / 1024).toFixed(1)} KB</td>
                    <td>
                        <button class="btn btn-sm btn-info" onclick="viewReport('${scan.filename}')">
                            👁️ Voir
                        </button>
                    </td>
                </tr>
            `).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="5">Aucun scan dans l\'historique</td></tr>';
        }
    } catch (error) {
        console.error('Erreur lors du chargement de l\'historique:', error);
        showNotification('Erreur lors du chargement de l\'historique: ' + error.message, 'error');
    }
}

async function viewReport(filename) {
    try {
        const response = await debugFetch(`/nuclei/report/${filename}`);
        const data = await response.json();
        
        if (response.ok) {
            displayResults(data);
            document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
        } else {
            showNotification('Erreur: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Erreur: ' + error.message, 'error');
    }
}
