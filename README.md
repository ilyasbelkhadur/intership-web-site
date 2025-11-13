# One-Time Password App avec Système d'Authentification

Cette application permet de créer et partager des mots de passe temporaires avec un système d'authentification complet.

## Fonctionnalités

- ✅ Système d'authentification (inscription/connexion)
- ✅ Gestion des sessions utilisateur
- ✅ Création de mots de passe temporaires
- ✅ Envoi de mots de passe par email
- ✅ **Historique complet des mots de passe envoyés**
- ✅ **Statistiques des mots de passe (actifs, utilisés, expirés)**
- ✅ **Affichage masqué des mots de passe avec bouton Afficher/Masquer**
- ✅ **Gestion des mots de passe (suppression, consultation)**
- ✅ Tableau de bord utilisateur avec statistiques
- ✅ Interface moderne et responsive
- ✅ Pages de consultation sans header pour plus de sécurité

## Prérequis

- Node.js (version 14 ou supérieure)
- MySQL/MariaDB
- Compte Gmail pour l'envoi d'emails

## Installation

1. **Cloner le projet**
   ```bash
   git clone <votre-repo>
   cd APP
   ```

2. **Installer les dépendances**
   ```bash
   npm install
   ```

3. **Configurer la base de données**

   Créez la base de données `pegase` dans phpMyAdmin et exécutez ces requêtes SQL :

   ```sql
   -- Table des utilisateurs
   CREATE TABLE users (
       user_id INT AUTO_INCREMENT PRIMARY KEY,
       username VARCHAR(255) NOT NULL UNIQUE,
       email VARCHAR(255) NOT NULL UNIQUE,
       password VARCHAR(255),
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
       last_login TIMESTAMP,
       status ENUM('active', 'inactive') DEFAULT 'active'
   );
   
   -- Table des mots de passe (sécurisée - ne stocke pas les mots de passe)
   CREATE TABLE passwords (
       password_id INT AUTO_INCREMENT PRIMARY KEY,
       user_id INT NULL,
       recipient_email VARCHAR(255) NOT NULL,
       expiration_time TIMESTAMP NULL,
       is_used BOOLEAN DEFAULT FALSE,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       used_at TIMESTAMP NULL,
       status ENUM('active', 'expired', 'used') DEFAULT 'active',
       can_view_secret BOOLEAN DEFAULT TRUE,
       FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
   );
   
   -- Index pour améliorer les performances
   CREATE INDEX idx_user_id ON passwords(user_id);
   CREATE INDEX idx_recipient_email ON passwords(recipient_email);
   CREATE INDEX idx_status ON passwords(status);
   CREATE INDEX idx_created_at ON passwords(created_at);
   ```

4. **Configurer les variables d'environnement**

   Créez un fichier `.env` à la racine du projet :

   ```env
   # Configuration de la base de données MySQL
   DB_HOST=localhost
   DB_USER=root
   DB_PASSWORD=votre_mot_de_passe_mysql
   DB_NAME=pegase

   # Configuration de l'email (Gmail)
   EMAIL_USER=votre_email@gmail.com
   EMAIL_PASS=votre_mot_de_passe_d_application_gmail

   # Configuration du serveur
   PORT=3000

   # Clé secrète pour les sessions
   SESSION_SECRET=votre_cle_secrete_tres_longue_et_complexe
   ```

   **Note pour Gmail :** Vous devez activer l'authentification à deux facteurs et générer un mot de passe d'application.

5. **Démarrer l'application**
   ```bash
   npm start
   ```

   L'application sera accessible à l'adresse : http://localhost:3000

## Structure du projet

```
APP/
├── config/
│   └── database.js          # Configuration de la base de données
├── middleware/
│   └── auth.js              # Middleware d'authentification
├── models/
│   ├── User.js              # Modèle utilisateur
│   └── Password.js          # Modèle mots de passe
├── views/
│   ├── login.ejs            # Page de connexion
│   ├── register.ejs         # Page d'inscription
│   ├── dashboard.ejs        # Tableau de bord
│   ├── secret.ejs           # Page d'affichage des mots de passe
│   ├── used.ejs             # Page d'erreur (mot de passe expiré)
│   └── partials/
│       └── header.ejs       # Header avec navigation
├── app.js                   # Application principale
├── create_secret.js         # Logique de création des secrets
├── email.html               # Template d'email
└── package.json
```

## Routes disponibles

- `GET /` - Page d'accueil (création de mots de passe)
- `GET /login` - Page de connexion
- `POST /login` - Traitement de la connexion
- `GET /register` - Page d'inscription
- `POST /register` - Traitement de l'inscription
- `GET /dashboard` - Tableau de bord (authentification requise)
- `GET /logout` - Déconnexion
- `POST /create` - Création d'un mot de passe
- `GET /password/:key` - Affichage d'un mot de passe (nouvelle route)
- `GET /secret/:key` - Affichage d'un mot de passe (route de compatibilité)
- `POST /delete-password/:id` - Suppression d'un mot de passe (authentification requise)
- `POST /request-new-password` - Demande de nouveau mot de passe

## Fonctionnalités avancées

### Historique des mots de passe
- Affichage de tous les mots de passe envoyés
- Statistiques détaillées (total, actifs, utilisés, expirés)
- Pagination pour les grandes listes
- Mots de passe masqués par défaut avec bouton Afficher/Masquer

### Sécurité
- Les mots de passe sont hashés avec bcrypt
- Sessions sécurisées avec des cookies
- Protection CSRF intégrée
- Validation des données côté serveur
- Gestion des erreurs
- Pages de consultation sans header pour plus de sécurité

### Interface utilisateur
- Design moderne et responsive
- Masquage automatique des mots de passe sensibles
- Boutons d'action intuitifs
- Messages de confirmation et d'erreur

## Support

Pour toute question ou problème, veuillez créer une issue sur le repository. 