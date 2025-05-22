// Fonction pour soumettre le formulaire de découverte réseau
function submitNetworkDiscovery() {
    const form = document.getElementById('network-discovery-form');
    const submitBtn = document.getElementById('start-discovery-btn');
    
    if (form && submitBtn) {
        form.addEventListener('submit', function() {
            submitBtn.disabled = true;
            submitBtn.textContent = 'Analyse en cours...';
        });
    }
}

// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    submitNetworkDiscovery();
});
