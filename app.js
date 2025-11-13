const express = require('express');
const path = require('path');
const createSecret = require('./create_secret');
const getSecret = createSecret.getSecret;
const nodemailer = require('nodemailer');
require('dotenv').config();
const fs = require('fs');
const session = require('express-session');
const User = require('./models/User');
const Password = require('./models/Password');
const { requireAuth, requireGuest } = require('./middleware/auth');

console.log('createSecret au démarrage:', createSecret);
console.log('typeof createSecret:', typeof createSecret);

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 heures
  }
}));

// Middleware pour passer les informations utilisateur à toutes les vues
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  next();
});

// Middleware de protection globale - toutes les routes sauf celles explicitement autorisées
app.use((req, res, next) => {
  // Routes publiques autorisées
  const publicRoutes = [
    '/login',
    '/register', 
    '/pegase2695estc',
    '/verify-otp',
    '/resend-otp',
    '/logout'
  ];
  
  // Routes avec paramètres dynamiques (mots de passe partagés)
  const publicPatterns = [
    /^\/secret\/[a-zA-Z0-9]+$/,
    /^\/password\/[a-zA-Z0-9]+$/
  ];
  
  // Vérifier si la route est publique
  const isPublicRoute = publicRoutes.includes(req.path) || 
                       publicPatterns.some(pattern => pattern.test(req.path));
  
  // Si ce n'est pas une route publique et que l'utilisateur n'est pas connecté
  if (!isPublicRoute && !req.session.userId) {
    return res.redirect('/login');
  }
  
  next();
});

// Middleware pour mettre à jour les mots de passe expirés
app.use(async (req, res, next) => {
  try {
    await Password.updateExpiredPasswords();
  } catch (error) {
    console.error('Erreur lors de la mise à jour des mots de passe expirés:', error);
  }
  next();
});

app.get('/', (req, res) => {
  // Si l'utilisateur n'est pas connecté, rediriger vers la page de login
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  // Si l'utilisateur est connecté, rediriger vers le dashboard
  res.redirect('/dashboard');
});

// Page pour créer/envoyer un mot de passe
app.get('/index', (req, res) => {
  const error = req.session.error;
  const success = req.session.success;
  req.session.error = undefined;
  req.session.success = undefined;
  res.render('index', { error, success });
});

// Routes d'authentification
app.get('/login', requireGuest, (req, res) => {
  const error = req.session.error;
  const success = req.session.success;
  req.session.error = undefined;
  req.session.success = undefined;
  res.render('login', { error, success });
});

app.post('/login', requireGuest, async (req, res) => {
  try {
    // Accepter identifier, email ou username et nettoyer les espaces
    const rawIdentifier = (req.body.identifier || req.body.email || req.body.username || '').toString();
    const rawPassword = (req.body.password || '').toString();
    const identifier = rawIdentifier.trim();
    const password = rawPassword.trim();
    
    // Validation des données
    if (!identifier || !password) {
      req.session.error = 'Tous les champs sont requis';
      return res.redirect('/login');
    }
    
    // Rechercher l'utilisateur par email ou nom d'utilisateur
    let user = null;
    
    // Vérifier si l'identifiant ressemble à un email
    if (identifier.includes('@')) {
      user = await User.findByEmail(identifier);
    } else {
      // Sinon, chercher par nom d'utilisateur
      user = await User.findByUsername(identifier);
    }
    
    if (!user) {
      req.session.error = 'Identifiant ou mot de passe incorrect';
      return res.redirect('/login');
    }
    
    // Vérifier le mot de passe
    const isValidPassword = await User.verifyPassword(password, user.password);
    if (!isValidPassword) {
      req.session.error = 'Identifiant ou mot de passe incorrect';
      return res.redirect('/login');
    }
    
    // Vérifier le statut de l'utilisateur
    if (user.status !== 'active') {
      req.session.error = 'Votre compte est désactivé';
      return res.redirect('/login');
    }
    
    // Étape OTP: générer un code à usage unique et l'envoyer par email
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + (10 * 60 * 1000); // 10 minutes

    // Stocker dans la session (sans connecter l'utilisateur pour l'instant)
    req.session.pendingUser = {
      user_id: user.user_id,
      username: user.username,
      email: user.email
    };
    req.session.pendingOtp = { code: otpCode, expiresAt };
    req.session.otpAttempts = 0;

    // Envoyer l'OTP par email
    try {
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      });

      const mailOptions = {
        from: `Sécurité OTP <${process.env.EMAIL_USER}>`,
        to: user.email,
        subject: 'Votre code de vérification (OTP)',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #f49e12;">Code de vérification</h2>
            <p>Bonjour ${user.username},</p>
            <p>Utilisez le code ci-dessous pour finaliser votre connexion :</p>
            <p style="font-size: 28px; letter-spacing: 4px; font-weight: bold;">${otpCode}</p>
            <p>Ce code expire dans <strong>10 minutes</strong>.</p>
            <hr>
            <p style="color:#666; font-size: 12px;">Si vous n'êtes pas à l'origine de cette demande, vous pouvez ignorer cet email.</p>
          </div>
        `
      };

      await transporter.sendMail(mailOptions);
      req.session.success = 'Un code de vérification a été envoyé à votre email.';
      return res.redirect('/verify-otp');
    } catch (err) {
      console.error('Erreur lors de l\'envoi de l\'OTP:', err);
      req.session.error = 'Impossible d\'envoyer le code de vérification. Réessayez plus tard.';
      return res.redirect('/login');
    }
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    req.session.error = 'Erreur lors de la connexion';
    res.redirect('/login');
  }
});

// Page de vérification OTP
app.get('/verify-otp', requireGuest, (req, res) => {
  if (!req.session.pendingUser || !req.session.pendingOtp) {
    return res.redirect('/login');
  }
  const error = req.session.error;
  const success = req.session.success;
  req.session.error = undefined;
  req.session.success = undefined;
  res.render('verify-otp', { error, success, email: req.session.pendingUser.email });
});

app.post('/verify-otp', requireGuest, async (req, res) => {
  try {
    const inputCode = (req.body.code || '').toString().trim();
    const pendingOtp = req.session.pendingOtp;
    const pendingUser = req.session.pendingUser;

    if (!pendingOtp || !pendingUser) {
      req.session.error = 'Session de vérification expirée. Veuillez vous reconnecter.';
      return res.redirect('/login');
    }

    if (!inputCode) {
      req.session.error = 'Veuillez saisir le code de vérification.';
      return res.redirect('/verify-otp');
    }

    if (Date.now() > pendingOtp.expiresAt) {
      req.session.error = 'Le code a expiré. Veuillez vous reconnecter.';
      req.session.pendingOtp = undefined;
      req.session.pendingUser = undefined;
      return res.redirect('/login');
    }

    // Vérifier le code
    if (inputCode !== pendingOtp.code) {
      req.session.otpAttempts = (req.session.otpAttempts || 0) + 1;
      if (req.session.otpAttempts >= 5) {
        req.session.error = 'Trop de tentatives. Veuillez vous reconnecter.';
        req.session.pendingOtp = undefined;
        req.session.pendingUser = undefined;
        req.session.otpAttempts = 0;
        return res.redirect('/login');
      }
      req.session.error = 'Code invalide. Veuillez réessayer.';
      return res.redirect('/verify-otp');
    }

    // Succès: finaliser la connexion
    req.session.userId = pendingUser.user_id;
    req.session.user = {
      user_id: pendingUser.user_id,
      username: pendingUser.username,
      email: pendingUser.email
    };

    // Mettre à jour la dernière connexion maintenant que l'utilisateur est authentifié
    try { await User.updateLastLogin(pendingUser.user_id); } catch (e) { console.error('Maj last_login échouée:', e); }

    // Envoyer une notification de connexion par email
    try {
      const transporter = nodemailer.createTransporter({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      });

      // Obtenir les informations de l'appareil et de la localisation
      const userAgent = req.headers['user-agent'] || 'Appareil inconnu';
      const ipAddress = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'IP inconnue';
      const currentTime = new Date().toLocaleString('fr-FR', { 
        timeZone: 'Europe/Paris',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });

      const mailOptions = {
        from: `Sécurité PEGASE <${process.env.EMAIL_USER}>`,
        to: pendingUser.email,
        subject: '🔔 Nouvelle connexion détectée - PEGASE Expert',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f8f9fa; padding: 20px;">
            <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
              <div style="text-align: center; margin-bottom: 30px;">
                <h2 style="color: #f49e12; margin: 0;">🔔 Nouvelle connexion détectée</h2>
                <p style="color: #666; margin: 10px 0;">Bonjour ${pendingUser.username},</p>
              </div>
              
              <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                <h3 style="color: #856404; margin: 0 0 15px 0;">📱 Détails de la connexion</h3>
                <div style="margin-bottom: 10px;">
                  <strong style="color: #333;">⏰ Date et heure :</strong>
                  <span style="color: #666;"> ${currentTime}</span>
                </div>
                <div style="margin-bottom: 10px;">
                  <strong style="color: #333;">🌐 Adresse IP :</strong>
                  <span style="color: #666;"> ${ipAddress}</span>
                </div>
                <div style="margin-bottom: 10px;">
                  <strong style="color: #333;">💻 Appareil :</strong>
                  <span style="color: #666;"> ${userAgent}</span>
                </div>
              </div>
              
              <div style="background: #d1ecf1; border: 1px solid #bee5eb; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                <h3 style="color: #0c5460; margin: 0 0 15px 0;">🛡️ Sécurité</h3>
                <p style="color: #0c5460; margin: 0; line-height: 1.6;">
                  Si cette connexion ne vous appartient pas, nous vous recommandons de :
                </p>
                <ul style="color: #0c5460; margin: 10px 0 0 0; padding-left: 20px;">
                  <li>Changer immédiatement votre mot de passe</li>
                  <li>Activer l'authentification à deux facteurs</li>
                  <li>Contacter notre support si nécessaire</li>
                </ul>
              </div>
              
              <div style="text-align: center; margin-top: 30px;">
                <p style="color: #666; font-size: 14px; margin: 0;">
                  Cette notification est envoyée automatiquement pour votre sécurité.
                </p>
                <p style="color: #666; font-size: 12px; margin: 10px 0 0 0;">
                  © 2024 PEGASE Expert - Tous droits réservés
                </p>
              </div>
            </div>
          </div>
        `
      };

      await transporter.sendMail(mailOptions);
      console.log('✅ Notification de connexion envoyée à', pendingUser.email);
    } catch (err) {
      console.error('❌ Erreur lors de l\'envoi de la notification de connexion:', err);
      // On continue même si l'envoi de notification échoue
    }

    // Nettoyer les données temporaires
    req.session.pendingOtp = undefined;
    req.session.pendingUser = undefined;
    req.session.otpAttempts = 0;

    req.session.success = 'Connexion vérifiée !';
    return res.redirect('/index');
  } catch (err) {
    console.error('Erreur vérification OTP:', err);
    req.session.error = 'Erreur lors de la vérification du code.';
    return res.redirect('/verify-otp');
  }
});

// Renvoyer un nouveau code OTP
app.get('/resend-otp', requireGuest, async (req, res) => {
  try {
    const pendingUser = req.session.pendingUser;
    if (!pendingUser) {
      req.session.error = 'Session expirée. Veuillez vous reconnecter.';
      return res.redirect('/login');
    }

    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + (10 * 60 * 1000);
    req.session.pendingOtp = { code: otpCode, expiresAt };

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });

    const mailOptions = {
      from: `Sécurité OTP <${process.env.EMAIL_USER}>`,
      to: pendingUser.email,
      subject: 'Votre nouveau code de vérification (OTP)',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #f49e12;">Nouveau code de vérification</h2>
          <p>Bonjour ${pendingUser.username},</p>
          <p>Utilisez le code ci-dessous pour finaliser votre connexion :</p>
          <p style=\"font-size: 28px; letter-spacing: 4px; font-weight: bold;\">${otpCode}</p>
          <p>Ce code expire dans <strong>10 minutes</strong>.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    req.session.success = 'Un nouveau code a été envoyé à votre email.';
    return res.redirect('/verify-otp');
  } catch (err) {
    console.error('Erreur lors du renvoi de l\'OTP:', err);
    req.session.error = 'Impossible d\'envoyer un nouveau code. Réessayez plus tard.';
    return res.redirect('/verify-otp');
  }
});

app.get('/register', requireGuest, (req, res) => {
  const error = req.session.error;
  const success = req.session.success;
  req.session.error = undefined;
  req.session.success = undefined;
  res.render('pegase2695estc', { error, success });
});

// Alias route to access the same registration view directly
app.get('/pegase2695estc', (req, res) => {
  const error = req.session.error;
  const success = req.session.success;
  req.session.error = undefined;
  req.session.success = undefined;
  res.render('pegase2695estc', { error, success });
});

app.post('/register', requireGuest, async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;
    
    // Validation des données
    if (!username || !email || !password || !confirmPassword) {
      req.session.error = 'Tous les champs sont requis';
      return res.redirect('/register');
    }
    
    if (password !== confirmPassword) {
      req.session.error = 'Les mots de passe ne correspondent pas';
      return res.redirect('/register');
    }
    
    if (password.length < 6) {
      req.session.error = 'Le mot de passe doit contenir au moins 6 caractères';
      return res.redirect('/register');
    }
    
    // Vérifier si l'email existe déjà
    const existingUserByEmail = await User.findByEmail(email);
    if (existingUserByEmail) {
      req.session.error = 'Cet email est déjà utilisé';
      return res.redirect('/register');
    }
    
    // Vérifier si le nom d'utilisateur existe déjà
    const existingUserByUsername = await User.findByUsername(username);
    if (existingUserByUsername) {
      req.session.error = 'Ce nom d\'utilisateur est déjà utilisé';
      return res.redirect('/register');
    }
    
    // Créer l'utilisateur
    const userId = await User.create(username, email, password);
    
    req.session.success = 'Inscription réussie ! Vous pouvez maintenant vous connecter.';
    res.redirect('/login');
  } catch (error) {
    console.error('Erreur lors de l\'inscription:', error);
    req.session.error = 'Erreur lors de l\'inscription';
    res.redirect('/register');
  }
});

app.get('/dashboard', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    
    const [user, stats, allPasswords] = await Promise.all([
      User.findByEmail(req.session.user.email),
      Password.getUserStats(req.session.userId).catch(() => null),
      Password.findByUserId(req.session.userId, limit, offset).catch(() => [])
    ]);
    
    const totalPasswords = stats ? stats.total_passwords : 0;
    const totalPages = Math.ceil(totalPasswords / limit);
    
    res.render('dashboard', { 
      user, 
      stats: stats || { total_passwords: 0, active_passwords: 0, used_passwords: 0, expired_passwords: 0 }, 
      passwords: allPasswords || [],
      currentPage: page,
      totalPages: totalPages || 1,
      error: req.session.error,
      success: req.session.success
    });
    
    req.session.error = undefined;
    req.session.success = undefined;
  } catch (error) {
    console.error('Erreur lors du chargement du dashboard:', error);
    req.session.error = 'Erreur lors du chargement du dashboard';
    res.redirect('/login');
  }
});

app.get('/profile', async (req, res) => {
  try {
    const user = await User.findByEmail(req.session.user.email);
    const error = req.session.error;
    const success = req.session.success;
    req.session.error = undefined;
    req.session.success = undefined;
    res.render('profile', { user, error, success });
  } catch (error) {
    console.error('Erreur lors du chargement du profil:', error);
    req.session.error = 'Erreur lors du chargement du profil';
    res.redirect('/dashboard');
  }
});

app.post('/profile', async (req, res) => {
  try {
    const { username, email, currentPassword } = req.body;
    
    // Validation des données
    if (!username || !email || !currentPassword) {
      req.session.error = 'Tous les champs sont requis';
      return res.redirect('/profile');
    }
    
    // Récupérer l'utilisateur actuel
    const currentUser = await User.findByEmail(req.session.user.email);
    if (!currentUser) {
      req.session.error = 'Utilisateur non trouvé';
      return res.redirect('/profile');
    }
    
    // Vérifier le mot de passe actuel
    const isValidPassword = await User.verifyPassword(currentPassword, currentUser.password);
    if (!isValidPassword) {
      req.session.error = 'Mot de passe actuel incorrect';
      return res.redirect('/profile');
    }
    
    // Vérifier si l'email existe déjà (sauf pour l'utilisateur actuel)
    if (email !== currentUser.email) {
      const existingUserByEmail = await User.findByEmail(email);
      if (existingUserByEmail) {
        req.session.error = 'Cet email est déjà utilisé par un autre compte';
        return res.redirect('/profile');
      }
    }
    
    // Vérifier si le nom d'utilisateur existe déjà (sauf pour l'utilisateur actuel)
    if (username !== currentUser.username) {
      const existingUserByUsername = await User.findByUsername(username);
      if (existingUserByUsername) {
        req.session.error = 'Ce nom d\'utilisateur est déjà utilisé par un autre compte';
        return res.redirect('/profile');
      }
    }
    
    // Mettre à jour le profil
    await User.updateProfile(currentUser.user_id, username, email);
    
    // Mettre à jour la session
    req.session.user.username = username;
    req.session.user.email = email;
    
    req.session.success = 'Profil mis à jour avec succès !';
    res.redirect('/profile');
  } catch (error) {
    console.error('Erreur lors de la mise à jour du profil:', error);
    req.session.error = 'Erreur lors de la mise à jour du profil';
    res.redirect('/profile');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Erreur lors de la déconnexion:', err);
    }
    res.redirect('/');
  });
});

// Route pour supprimer un mot de passe de l'historique
app.post('/delete-password/:passwordId', async (req, res) => {
  try {
    const passwordId = parseInt(req.params.passwordId);
    const deleted = await Password.deleteByUserId(passwordId, req.session.userId);
    
    if (deleted) {
      req.session.success = 'Mot de passe supprimé de votre historique avec succès';
    } else {
      req.session.error = 'Mot de passe non trouvé ou vous n\'avez pas les permissions pour le supprimer';
    }
    
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Erreur lors de la suppression du mot de passe:', error);
    req.session.error = 'Erreur lors de la suppression du mot de passe';
    res.redirect('/dashboard');
  }
});

app.post('/create', async (req, res) => {
  console.log('createSecret dans POST /create:', createSecret);
  console.log('Body complet:', req.body);
  
  const secret = req.body.secret;
  const email = req.body.email;
  const expiration = req.body.expiration;
  
  console.log('Valeurs extraites:');
  console.log('- secret:', secret);
  console.log('- email:', email);
  console.log('- expiration:', expiration);
  
  const result = await createSecret(secret);

  // Stocker l'email dans la session pour récupération ultérieure
  req.session.userEmail = email;

  // Extraire la clé depuis l'URL retournée par createSecret
  const passwordKey = result.url.split('/').pop();
  
  console.log('Tentative de sauvegarde du mot de passe...');
  console.log('Session userId:', req.session.userId);
  console.log('Password key:', passwordKey);
  console.log('Email:', email);
  console.log('Expiration sélectionnée:', expiration);

  // Sauvegarder le mot de passe dans la base de données
  try {
    let expirationTime = null;
    if (expiration && expiration !== 'never') {
      const now = new Date();
      console.log('Date actuelle:', now);
      
      switch (expiration) {
        case '1m':
          expirationTime = new Date(now.getTime() + 1 * 60 * 1000);
          break;
        case '5m':
          expirationTime = new Date(now.getTime() + 5 * 60 * 1000);
          break;
        case '10m':
          expirationTime = new Date(now.getTime() + 10 * 60 * 1000);
          break;
        case '30m':
          expirationTime = new Date(now.getTime() + 30 * 60 * 1000);
          break;
        case '1h':
          expirationTime = new Date(now.getTime() + 60 * 60 * 1000);
          break;
        case '24h':
          expirationTime = new Date(now.getTime() + 24 * 60 * 60 * 1000);
          break;
        case '7d':
          expirationTime = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
          break;
      }
      
      console.log('Expiration calculée:', expirationTime);
    }
    
    // Si l'utilisateur est connecté, sauvegarder avec son ID, sinon avec null
    const userId = req.session.userId || null;
    
    console.log('Paramètres pour Password.create:');
    console.log('- userId:', userId);
    console.log('- passwordKey:', passwordKey);
    console.log('- secret:', secret);
    console.log('- email:', email);
    console.log('- expirationTime:', expirationTime);
    
    await Password.create(
      userId,
      email,
      expirationTime,
      passwordKey
    );
    
    if (userId) {
      console.log('✅ Mot de passe sauvegardé avec succès dans la base de données (utilisateur connecté)');
    } else {
      console.log('✅ Mot de passe sauvegardé avec succès dans la base de données (utilisateur non connecté)');
    }
    } catch (error) {
    console.error('❌ Erreur lors de la sauvegarde du mot de passe:', error);
    // On continue même si la sauvegarde échoue
  }

  // Charger le template d'email
  let emailHtml = fs.readFileSync('email.html', 'utf8');
  // Remplacer seulement le lien par le lien du mot de passe
  const passwordUrl = result.url.replace('/secret/', '/password/');
  emailHtml = emailHtml.replace(/https:\/\/pegase\.expert/g, `http://localhost:3000${passwordUrl}`);

  // Configurer le transporteur Nodemailer (exemple avec Gmail, à adapter selon le provider)
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER, // à définir dans .env
      pass: process.env.EMAIL_PASS  // à définir dans .env
    }
  });

  // Préparer le mail
  const mailOptions = {
    from: `Mot de passe Sender <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Votre lien mot de passe One-Time',
    html: emailHtml
  };

  // Envoyer le mail
  try {
    await transporter.sendMail(mailOptions);
    req.session.success = 'Le lien mot de passe a été envoyé avec succès à ' + email;
    res.redirect('/index');
  } catch (err) {
    console.error('Erreur lors de l\'envoi de l\'email:', err);
    req.session.error = "Erreur lors de l'envoi de l'email: " + err.message;
    res.redirect('/index');
  }
});

// Route pour accéder aux mots de passe (compatibilité avec les anciens liens)
app.get('/secret/:key', async (req, res) => {
  try {
    // Vérifier d'abord si le mot de passe existe dans la base de données
    const dbPassword = await Password.findByKey(req.params.key);
    
    if (dbPassword) {
      // Vérifier si le mot de passe a expiré
      if (dbPassword.expiration_time && new Date(dbPassword.expiration_time) < new Date()) {
        // Marquer comme expiré si ce n'est pas déjà fait
        if (dbPassword.status !== 'expired') {
          await Password.updateExpiredPasswords();
        }
        return res.render('used', { message: 'Ce mot de passe a expiré.' });
      }
      
      // Vérifier si le mot de passe a déjà été utilisé
      if (dbPassword.is_used || dbPassword.status === 'used') {
        return res.render('used', { message: 'Ce mot de passe a déjà été utilisé.' });
      }
    }
    
    const secret = await getSecret(req.params.key);
    
    // Marquer le mot de passe comme utilisé dans la base de données
    try {
      if (dbPassword && !dbPassword.is_used && dbPassword.status !== 'used') {
        await Password.markAsUsed(dbPassword.password_id);
        console.log('✅ Mot de passe marqué comme utilisé:', dbPassword.password_id);
      }
    } catch (error) {
      console.error('❌ Erreur lors de la mise à jour du statut:', error);
      // On continue même si la mise à jour échoue
    }
    
    res.render('secret', { secret });
  } catch (error) {
    console.error('❌ Erreur lors de l\'accès au mot de passe:', error);
    res.render('used', { message: 'Ce mot de passe n\'existe pas ou a expiré.' });
  }
});

// Nouvelle route pour les mots de passe
app.get('/password/:key', async (req, res) => {
  try {
    // Vérifier d'abord si le mot de passe existe dans la base de données
    const dbPassword = await Password.findByKey(req.params.key);
    
    if (dbPassword) {
      // Vérifier si le mot de passe a expiré
      if (dbPassword.expiration_time && new Date(dbPassword.expiration_time) < new Date()) {
        // Marquer comme expiré si ce n'est pas déjà fait
        if (dbPassword.status !== 'expired') {
          await Password.updateExpiredPasswords();
        }
        return res.render('used', { message: 'Ce mot de passe a expiré.' });
      }
      
      // Vérifier si le mot de passe a déjà été utilisé
      if (dbPassword.is_used || dbPassword.status === 'used') {
        return res.render('used', { message: 'Ce mot de passe a déjà été utilisé.' });
      }
    }
    
    const secret = await getSecret(req.params.key);
    
    // Marquer le mot de passe comme utilisé dans la base de données
    try {
      if (dbPassword && !dbPassword.is_used && dbPassword.status !== 'used') {
        await Password.markAsUsed(dbPassword.password_id);
        console.log('✅ Mot de passe marqué comme utilisé:', dbPassword.password_id);
      }
    } catch (error) {
      console.error('❌ Erreur lors de la mise à jour du statut:', error);
      // On continue même si la mise à jour échoue
    }
    
    res.render('secret', { secret });
  } catch (error) {
    console.error('❌ Erreur lors de l\'accès au mot de passe:', error);
    res.render('used', { message: 'Ce mot de passe n\'existe pas ou a expiré.' });
  }
});

app.post('/request-new-password', async (req, res) => {
  try {
    // Récupérer l'email depuis la session
    const userEmail = req.session.userEmail || 'Email non disponible';
    
    // Créer un email simple de notification
    const emailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #f49e12;">Demande de nouveau mot de passe</h2>
        <p>Un utilisateur a demandé un nouveau mot de passe.</p>
        <p><strong>Email de l'utilisateur:</strong> ${userEmail}</p>
        <p><strong>Date de la demande:</strong> ${new Date().toLocaleString('fr-FR')}</p>
        <hr>
        <p>Veuillez traiter cette demande manuellement et envoyer un nouveau mot de passe à l'utilisateur.</p>
      </div>
    `;
    
    // Configurer le transporteur Nodemailer
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    // Préparer le mail pour la demande de nouveau mot de passe
    const mailOptions = {
      from: `Mot de passe Sender <${process.env.EMAIL_USER}>`,
      to: 'ilyasbelkhadir1234@gmail.com',
      subject: 'Demande de nouveau mot de passe - Traitement requis',
      html: emailHtml
    };

    // Envoyer le mail
    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: 'Demande envoyée avec succès' });
  } catch (err) {
    console.error('Erreur lors de l\'envoi de l\'email de demande:', err);
    res.status(500).json({ success: false, message: 'Erreur lors de l\'envoi de la demande' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});