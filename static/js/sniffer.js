// Fonction pour charger la liste des interfaces réseau
function loadInterfaces() {
    const selectElement = document.getElementById('interface');
    if (!selectElement) return;
    
    // Afficher un message de chargement
    selectElement.innerHTML = '<option value="">Chargement des interfaces...</option>';
    
    // Récupérer la liste des interfaces via l'API
    fetch('/api/sniffer/interfaces')
        .then(response => {
            if (!response.ok) {
                throw new Error('Réponse réseau non valide');
            }
            return response.json();
        })
        .then(data => {
            // Vider la liste
            selectElement.innerHTML = '';
            
            if (data.interfaces && data.interfaces.length > 0) {
                // Ajouter chaque interface à la liste
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface.name;
                    option.textContent = `${iface.name} - ${iface.description || 'N/A'}`;
                    selectElement.appendChild(option);
                });
            } else {
                // Aucune interface trouvée ou erreur
                const option = document.createElement('option');
                option.value = "";
                option.textContent = "Aucune interface disponible";
                selectElement.appendChild(option);
            }
        })
        .catch(error => {
            console.error('Erreur lors du chargement des interfaces:', error);
            selectElement.innerHTML = '<option value="">Erreur de chargement</option>';
        });
}

// Fonction pour soumettre le formulaire de capture
function submitCapture() {
    const form = document.getElementById('sniffer-form');
    const submitBtn = document.getElementById('start-capture-btn');
    
    if (form && submitBtn) {
        form.addEventListener('submit', function() {
            submitBtn.disabled = true;
            submitBtn.textContent = 'Capture en cours...';
        });
    }
}

// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    loadInterfaces();
    submitCapture();
});
