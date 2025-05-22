// static/js/vuln.js

// Ports prédéfinis par catégorie
const PORT_CATEGORIES = {
    "common": "21,22,23,25,80,110,139,143,443,445,3389",
    "web": "80,443,8080,8443,8000,8888",
    "database": "1433,1521,3306,5432,27017",
    "mail": "25,110,143,465,587,993,995",
    "file_transfer": "20,21,22,69,115,445",
    "remote_access": "22,23,3389,5900",
    "top100": "1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000"
};

// Mettre à jour les ports en fonction de la catégorie sélectionnée
document.getElementById('port-category').addEventListener('change', function() {
    const portsInput = document.getElementById('ports');
    const category = this.value;
    
    if (category === 'custom') {
        portsInput.readOnly = false;
        portsInput.style.backgroundColor = 'white';  // Retour à l'apparence normale
        portsInput.value = '';
        portsInput.placeholder = 'Entrez vos ports personnalisés';
    } else {
        // Remplir automatiquement mais permettre la modification
        portsInput.readOnly = false;  // Changé de true à false
        portsInput.style.backgroundColor = 'white';  // Pour indiquer que le champ est modifiable
        portsInput.value = PORT_CATEGORIES[category] || '';
    }
});

// Initialisation au chargement de la page
document.addEventListener('DOMContentLoaded', function() {
    // Définir la catégorie par défaut
    const categorySelect = document.getElementById('port-category');
    const portsInput = document.getElementById('ports');
    
    if (categorySelect && portsInput) {
        categorySelect.value = 'common';  // Définir la valeur par défaut
        portsInput.value = PORT_CATEGORIES['common'];
        portsInput.readOnly = false;  // S'assurer que le champ est modifiable
    }
});

// Gérer la soumission du formulaire
document.getElementById('vuln-form').addEventListener('submit', function(event) {
    const startBtn = document.getElementById('start-vuln-btn');
    startBtn.disabled = true;
    startBtn.textContent = 'Scan en cours...';
});
