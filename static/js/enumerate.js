// Fonction pour soumettre le formulaire d'énumération
function submitEnumeration() {
    const form = document.getElementById('enumeration-form');
    const submitBtn = document.getElementById('start-enumeration-btn');
    
    if (form && submitBtn) {
        form.addEventListener('submit', function() {
            submitBtn.disabled = true;
            submitBtn.textContent = 'Énumération en cours...';
        });
    }
}

// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    submitEnumeration();
});
