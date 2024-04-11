const usersRepository = require('./users-repository');
const { hashPassword } = require('../../../utils/password');
const { errorTypes, errorResponder } = require('../../../core/errors');
const bcrypt = require('bcrypt');

/**
 * Get list of users
 * @returns {Array}
 */
async function getUsers() {
  const users = await usersRepository.getUsers();

  const results = [];
  for (let i = 0; i < users.length; i += 1) {
    const user = users[i];
    results.push({
      id: user.id,
      name: user.name,
      email: user.email,
    });
  }

  return results;
}

/**
 * Get user detail
 * @param {string} id - User ID
 * @returns {Object}
 */
async function getUser(id) {
  const user = await usersRepository.getUser(id);

  // User not found
  if (!user) {
    return null;
  }

  return {
    id: user.id,
    name: user.name,
    email: user.email,
  };
}

/**
 * Create new user
 * @param {string} name - Name
 * @param {string} email - Email
 * @param {string} password - Password
 * @returns {boolean}
 */
async function createUser(name, email, password) {
  // Hash password
  const hashedPassword = await hashPassword(password);

  try {
    await usersRepository.createUser(name, email, hashedPassword);
  } catch (err) {
    return null;
  }

  return true;
}

/**
 * Update existing user
 * @param {string} id - User ID
 * @param {string} name - Name
 * @param {string} email - Email
 * @returns {boolean}
 */
async function updateUser(id, name, email) {
  const user = await usersRepository.getUser(id);

  // User not found
  if (!user) {
    return null;
  }

  try {
    await usersRepository.updateUser(id, name, email);
  } catch (err) {
    return null;
  }

  return true;
}
/**
 * compare old and new password
 * @param {string} realPassword
 * @param {string} hashedPassword
 * @returns {boolean}
 */
async function comparePassword(realPassword, hashedPassword) {
  return await bcrypt.compare(realPassword, hashedPassword);
}

/**
 * change password
 * @param {string} id - User ID
 * @param {string} oldPassword
 * @param {string} newPassword
 * @param {string} confirmPassword
 * @returns {boolean}
 */
async function changePassword(id, oldPassword, newPassword, confirmPassword) {
  const user = await usersRepository.getUser(id);
  if (!user) {
    return null;
  }

  const matchOldPassword = await comparePassword(oldPassword, user.password);
  if (!matchOldPassword) {
    return false;
  }

  const hashedPasswordNew = await hashPassword(newPassword);

  try {
    await usersRepository.changePassword(id, hashedPasswordNew);
  } catch (err) {
    return false;
  }
  return true;
}

/**
 * Delete user
 * @param {string} id - User ID
 * @returns {boolean}
 */
async function deleteUser(id) {
  const user = await usersRepository.getUser(id);

  // User not found
  if (!user) {
    return null;
  }

  try {
    await usersRepository.deleteUser(id);
  } catch (err) {
    return null;
  }

  return true;
}

/**
 * Validate if user email is unique
 * @param {Object} user - User object
 * @returns {Promise}
 */
async function isEmailTaken(email) {
  const exists = await usersRepository.checkEmailExists(email);
  return exists;
}

module.exports = {
  getUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
  isEmailTaken,
  changePassword,
  comparePassword,
};
