// Fonction pour charger les services supportés
function loadServices() {
    const selectElement = document.getElementById('service');
    if (!selectElement) return;
    
    // Afficher un message de chargement
    selectElement.innerHTML = '<option value="">Chargement des services...</option>';
    
    // Récupérer la liste des services via l'API
    fetch('/api/hydra/services', {
        headers: { 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Réponse réseau non valide');
        }
        return response.json();
    })
    .then(data => {
        // Vider la liste
        selectElement.innerHTML = '';
        
        // Option par défaut
        const defaultOption = document.createElement('option');
        defaultOption.value = "";
        defaultOption.textContent = "Sélectionnez un service";
        selectElement.appendChild(defaultOption);
        
        if (data.services && data.services.length > 0) {
            // Ajouter chaque service à la liste
            data.services.forEach(service => {
                const option = document.createElement('option');
                option.value = service.name;
                option.textContent = `${service.name} (${service.description} - port ${service.port})`;
                selectElement.appendChild(option);
            });
        } else {
            // Aucun service trouvé ou erreur
            const option = document.createElement('option');
            option.value = "";
            option.textContent = "Aucun service disponible";
            selectElement.appendChild(option);
        }
    })
    .catch(error => {
        console.error('Erreur lors du chargement des services:', error);
        selectElement.innerHTML = '<option value="">Erreur de chargement</option>';
    });
}

// Fonction pour charger les wordlists
function loadWordlists() {
    const userSelect = document.getElementById('userlist');
    const passSelect = document.getElementById('passlist');
    if (!userSelect || !passSelect) return;
    
    // Afficher un message de chargement
    userSelect.innerHTML = '<option value="">Chargement des listes...</option>';
    passSelect.innerHTML = '<option value="">Chargement des listes...</option>';
    
    // Récupérer la liste des wordlists via l'API
    fetch('/api/hydra/wordlists', {
        headers: { 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Réponse réseau non valide');
        }
        return response.json();
    })
    .then(data => {
        // Vider les listes
        userSelect.innerHTML = '';
        passSelect.innerHTML = '';
        
        // Option par défaut
        userSelect.innerHTML = '<option value="">Sélectionnez une liste d\'utilisateurs</option>';
        passSelect.innerHTML = '<option value="">Sélectionnez une liste de mots de passe</option>';
        
        // Ajouter les listes d'utilisateurs
        if (data.user_lists && data.user_lists.length > 0) {
            data.user_lists.forEach(list => {
                const option = document.createElement('option');
                option.value = list.path;
                option.textContent = list.name;
                userSelect.appendChild(option);
            });
        }
        
        // Ajouter les listes de mots de passe
        if (data.pass_lists && data.pass_lists.length > 0) {
            data.pass_lists.forEach(list => {
                const option = document.createElement('option');
                option.value = list.path;
                option.textContent = list.name;
                passSelect.appendChild(option);
            });
        }
    })
    .catch(error => {
        console.error('Erreur lors du chargement des wordlists:', error);
        userSelect.innerHTML = '<option value="">Erreur de chargement</option>';
        passSelect.innerHTML = '<option value="">Erreur de chargement</option>';
    });
}

// Fonction pour télécharger une wordlist
function uploadWordlist(file, listType) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('list_type', listType);
    
    const statusElement = document.getElementById(`${listType}-upload-status`);
    statusElement.innerHTML = '<span style="color: blue;">Téléchargement en cours...</span>';
    
    fetch('/api/hydra/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Erreur lors du téléchargement');
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            statusElement.innerHTML = `<span style="color: green;">✓ ${data.message}</span>`;
            
            // Recharger les wordlists pour voir le nouveau fichier
            loadWordlists();
            
            // Sélectionner automatiquement le fichier téléchargé après un délai
            setTimeout(() => {
                const selectElement = document.getElementById(listType === 'userlist' ? 'userlist' : 'passlist');
                for (let i = 0; i < selectElement.options.length; i++) {
                    if (selectElement.options[i].textContent === data.file_name) {
                        selectElement.selectedIndex = i;
                        break;
                    }
                }
            }, 1000); // Attendre un peu que les listes soient rechargées
        } else {
            statusElement.innerHTML = `<span style="color: red;">✗ ${data.error || 'Erreur inconnue'}</span>`;
        }
    })
    .catch(error => {
        console.error('Erreur lors du téléchargement:', error);
        statusElement.innerHTML = `<span style="color: red;">✗ Erreur de téléchargement: ${error.message}</span>`;
    });
}

// Gestionnaire d'événement pour les options HTTP
function handleServiceChange() {
    const httpOptions = document.getElementById('http-options');
    if (this.value && this.value.includes('http')) {
        httpOptions.style.display = 'block';
    } else {
        httpOptions.style.display = 'none';
    }
}

// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    // Charger les données
    loadServices();
    loadWordlists();
    
    // Gérer l'affichage des options HTTP
    const serviceSelect = document.getElementById('service');
    if (serviceSelect) {
        serviceSelect.addEventListener('change', handleServiceChange);
    }
    
    // Gérer l'affichage des champs de listes personnalisées
    const toggleCustomUser = document.getElementById('toggle-custom-userlist');
    if (toggleCustomUser) {
        toggleCustomUser.addEventListener('change', function() {
            document.getElementById('custom-userlist-container').style.display = this.checked ? 'block' : 'none';
            document.getElementById('userlist').disabled = this.checked;
            if (this.checked) {
                document.getElementById('upload-userlist-container').style.display = 'none';
            }
        });
    }
    
    const toggleCustomPass = document.getElementById('toggle-custom-passlist');
    if (toggleCustomPass) {
        toggleCustomPass.addEventListener('change', function() {
            document.getElementById('custom-passlist-container').style.display = this.checked ? 'block' : 'none';
            document.getElementById('passlist').disabled = this.checked;
            if (this.checked) {
                document.getElementById('upload-passlist-container').style.display = 'none';
            }
        });
    }
    
    // Gérer l'affichage des formulaires d'upload
    const uploadUserBtn = document.getElementById('upload-userlist-btn');
    if (uploadUserBtn) {
        uploadUserBtn.addEventListener('click', function() {
            const uploadContainer = document.getElementById('upload-userlist-container');
            uploadContainer.style.display = uploadContainer.style.display === 'none' ? 'block' : 'none';
            if (uploadContainer.style.display === 'block') {
                document.getElementById('toggle-custom-userlist').checked = false;
                document.getElementById('custom-userlist-container').style.display = 'none';
            }
        });
    }
    
    const uploadPassBtn = document.getElementById('upload-passlist-btn');
    if (uploadPassBtn) {
        uploadPassBtn.addEventListener('click', function() {
            const uploadContainer = document.getElementById('upload-passlist-container');
            uploadContainer.style.display = uploadContainer.style.display === 'none' ? 'block' : 'none';
            if (uploadContainer.style.display === 'block') {
                document.getElementById('toggle-custom-passlist').checked = false;
                document.getElementById('custom-passlist-container').style.display = 'none';
            }
        });
    }
    
    // Gérer les téléchargements de fichiers
    const submitUserUploadBtn = document.getElementById('submit-userlist-upload');
    if (submitUserUploadBtn) {
        submitUserUploadBtn.addEventListener('click', function() {
            const fileInput = document.getElementById('userlist-file');
            if (fileInput.files.length > 0) {
                uploadWordlist(fileInput.files[0], 'userlist');
            } else {
                document.getElementById('userlist-upload-status').innerHTML = '<span style="color: red;">✗ Veuillez sélectionner un fichier</span>';
            }
        });
    }
    
    const submitPassUploadBtn = document.getElementById('submit-passlist-upload');
    if (submitPassUploadBtn) {
        submitPassUploadBtn.addEventListener('click', function() {
            const fileInput = document.getElementById('passlist-file');
            if (fileInput.files.length > 0) {
                uploadWordlist(fileInput.files[0], 'passlist');
            } else {
                document.getElementById('passlist-upload-status').innerHTML = '<span style="color: red;">✗ Veuillez sélectionner un fichier</span>';
            }
        });
    }
    
    // Gérer la soumission du formulaire
    const hydraForm = document.getElementById('hydra-form');
    if (hydraForm) {
        hydraForm.addEventListener('submit', function(event) {
            const startBtn = document.getElementById('start-hydra-btn');
            startBtn.disabled = true;
            startBtn.innerHTML = 'Attaque en cours...';
            
            // Vérifier que soit une liste prédéfinie, soit une liste personnalisée est fournie
            const customUserList = document.getElementById('toggle-custom-userlist').checked;
            const customPassList = document.getElementById('toggle-custom-passlist').checked;
            
            if (!customUserList && !document.getElementById('userlist').value) {
                event.preventDefault();
                alert('Veuillez sélectionner une liste d\'utilisateurs ou fournir une liste personnalisée.');
                startBtn.disabled = false;
                startBtn.innerHTML = 'Lancer l\'attaque';
                return false;
            }
            
            if (!customPassList && !document.getElementById('passlist').value) {
                event.preventDefault();
                alert('Veuillez sélectionner une liste de mots de passe ou fournir une liste personnalisée.');
                startBtn.disabled = false;
                startBtn.innerHTML = 'Lancer l\'attaque';
                return false;
            }
        });
    }
});
