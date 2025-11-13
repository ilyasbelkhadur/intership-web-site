const db = require('../config/database');

class Password {
  // Créer un nouveau mot de passe
  static async create(userId, recipientEmail, expirationTime = null, passwordKey = null) {
    try {
      const [result] = await db.execute(
        'INSERT INTO passwords (user_id, recipient_email, expiration_time, password_key) VALUES (?, ?, ?, ?)',
        [userId, recipientEmail, expirationTime, passwordKey]
      );
      
      return result.insertId;
    } catch (error) {
      throw error;
    }
  }

  // Trouver un mot de passe par sa clé
  static async findByKey(passwordKey) {
    try {
      const [rows] = await db.execute(
        'SELECT * FROM passwords WHERE password_key = ? LIMIT 1',
        [passwordKey]
      );
      
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }

  // Marquer un mot de passe comme utilisé
  static async markAsUsed(passwordId) {
    try {
      await db.execute(
        'UPDATE passwords SET is_used = TRUE, used_at = CURRENT_TIMESTAMP, status = "used" WHERE password_id = ?',
        [passwordId]
      );
    } catch (error) {
      throw error;
    }
  }

  // Obtenir tous les mots de passe d'un utilisateur
  static async findByUserId(userId, limit = 50, offset = 0) {
    try {
      let query, params;
      
      if (userId) {
        // Utilisateur connecté : récupérer ses mots de passe
        query = `SELECT * FROM passwords 
                 WHERE user_id = ? 
                 ORDER BY created_at DESC 
                 LIMIT ? OFFSET ?`;
        params = [userId, limit, offset];
      } else {
        // Utilisateur non connecté : récupérer les mots de passe sans user_id
        query = `SELECT * FROM passwords 
                 WHERE user_id IS NULL 
                 ORDER BY created_at DESC 
                 LIMIT ? OFFSET ?`;
        params = [limit, offset];
      }
      
      const [rows] = await db.execute(query, params);
      return rows;
    } catch (error) {
      throw error;
    }
  }

  // Compter les mots de passe d'un utilisateur
  static async countByUserId(userId) {
    try {
      const [rows] = await db.execute(
        'SELECT COUNT(*) as count FROM passwords WHERE user_id = ?',
        [userId]
      );
      
      return rows[0].count;
    } catch (error) {
      throw error;
    }
  }

  // Obtenir les statistiques d'un utilisateur
  static async getUserStats(userId) {
    try {
      let query, params;
      
      if (userId) {
        // Utilisateur connecté : statistiques de ses mots de passe
        query = `SELECT 
          COUNT(*) as total_passwords,
          SUM(CASE WHEN is_used = TRUE THEN 1 ELSE 0 END) as used_passwords,
          SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_passwords,
          SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) as expired_passwords
         FROM passwords 
         WHERE user_id = ?`;
        params = [userId];
      } else {
        // Utilisateur non connecté : statistiques des mots de passe sans user_id
        query = `SELECT 
          COUNT(*) as total_passwords,
          SUM(CASE WHEN is_used = TRUE THEN 1 ELSE 0 END) as used_passwords,
          SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_passwords,
          SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) as expired_passwords
         FROM passwords 
         WHERE user_id IS NULL`;
        params = [];
      }
      
      const [rows] = await db.execute(query, params);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }

  // Supprimer un mot de passe de l'historique (pour l'utilisateur)
  static async deleteByUserId(passwordId, userId) {
    try {
      // Vérifier d'abord si le mot de passe appartient à l'utilisateur
      const [checkRows] = await db.execute(
        'SELECT password_id FROM passwords WHERE password_id = ? AND user_id = ?',
        [passwordId, userId]
      );
      
      if (checkRows.length === 0) {
        return false; // Le mot de passe n'existe pas ou n'appartient pas à l'utilisateur
      }
      
      // Supprimer le mot de passe
      const [result] = await db.execute(
        'DELETE FROM passwords WHERE password_id = ? AND user_id = ?',
        [passwordId, userId]
      );
      
      return result.affectedRows > 0;
    } catch (error) {
      throw error;
    }
  }

  // Mettre à jour le statut des mots de passe expirés
  static async updateExpiredPasswords() {
    try {
      const [result] = await db.execute(
        `UPDATE passwords 
         SET status = 'expired' 
         WHERE expiration_time IS NOT NULL 
         AND expiration_time < NOW() 
         AND status = 'active'`
      );
      
      if (result.affectedRows > 0) {
        console.log(`${result.affectedRows} mot(s) de passe marqué(s) comme expiré(s)`);
      }
      
      return result.affectedRows;
    } catch (error) {
      console.error('Erreur lors de la mise à jour des mots de passe expirés:', error);
      throw error;
    }
  }

  // Obtenir les mots de passe récents (pour le dashboard)
  static async getRecentPasswords(userId, limit = 5) {
    try {
      const [rows] = await db.execute(
        `SELECT * FROM passwords 
         WHERE user_id = ? 
         ORDER BY created_at DESC 
         LIMIT ?`,
        [userId, limit]
      );
      
      return rows;
    } catch (error) {
      throw error;
    }
  }
}

module.exports = Password; 