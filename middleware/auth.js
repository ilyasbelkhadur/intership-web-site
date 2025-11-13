// Middleware pour vérifier si l'utilisateur est connecté
function requireAuth(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
}

// Middleware pour vérifier si l'utilisateur n'est PAS connecté (pour les pages de login/register)
function requireGuest(req, res, next) {
  if (!req.session.userId) {
    next();
  } else {
    res.redirect('/dashboard');
  }
}

module.exports = {
  requireAuth,
  requireGuest
}; 