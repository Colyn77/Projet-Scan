// Fonction pour soumettre le formulaire de scan de ports
function submitPortScan() {
    const form = document.getElementById('portscan-form');
    const submitBtn = document.getElementById('start-portscan-btn');
    
    if (form && submitBtn) {
        form.addEventListener('submit', function() {
            submitBtn.disabled = true;
            submitBtn.textContent = 'Scan en cours...';
        });
    }
}

// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    submitPortScan();
});
