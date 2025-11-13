const db = require('../config/database');
const bcrypt = require('bcryptjs');

class User {
  // Créer un nouvel utilisateur
  static async create(username, email, password) {
    try {
      // Hasher le mot de passe
      const hashedPassword = await bcrypt.hash(password, 10);
      
      const [result] = await db.execute(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hashedPassword]
      );
      
      return result.insertId;
    } catch (error) {
      throw error;
    }
  }

  // Trouver un utilisateur par email
  static async findByEmail(email) {
    try {
      const [rows] = await db.execute(
        'SELECT * FROM users WHERE email = ?',
        [email]
      );
      
      return rows[0];
    } catch (error) {
      throw error;
    }
  }

  // Trouver un utilisateur par username
  static async findByUsername(username) {
    try {
      const [rows] = await db.execute(
        'SELECT * FROM users WHERE username = ?',
        [username]
      );
      
      return rows[0];
    } catch (error) {
      throw error;
    }
  }

  // Mettre à jour la dernière connexion
  static async updateLastLogin(userId) {
    try {
      await db.execute(
        'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?',
        [userId]
      );
    } catch (error) {
      throw error;
    }
  }

  // Mettre à jour le profil utilisateur
  static async updateProfile(userId, username, email) {
    try {
      await db.execute(
        'UPDATE users SET username = ?, email = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?',
        [username, email, userId]
      );
    } catch (error) {
      throw error;
    }
  }

  // Vérifier le mot de passe
  static async verifyPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
  }
}

module.exports = User; 