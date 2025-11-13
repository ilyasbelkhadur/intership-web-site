// In-memory store for passwords
const passwords = {};
const { randomBytes } = require('crypto');

// Create a new password and return a URL key
async function createSecret(password) {
  const key = randomBytes(16).toString('hex');
  passwords[key] = password;
  return { url: `/secret/${key}` };
}

// Retrieve a password by key and delete it after viewing (one-time)
async function getSecret(key) {
  const password = passwords[key];
  if (!password) throw new Error('Password not found');
  delete passwords[key]; // Remove after viewing
  return password;
}

module.exports = createSecret;
module.exports.getSecret = getSecret;
