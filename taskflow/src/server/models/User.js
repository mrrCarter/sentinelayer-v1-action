/**
 * User Model
 * Handles database operations for the users table.
 *
 * @module models/User
 */
const { db } = require('../config/database');
const bcrypt = require('bcryptjs');

const TABLE = 'users';

/**
 * @typedef {Object} User
 * @property {string} id - UUID primary key
 * @property {string} email - Unique email address
 * @property {string} password_hash - Bcrypt hashed password
 * @property {string} name - Display name
 * @property {string} role - 'user' | 'admin'
 * @property {string} plan - 'free' | 'pro' | 'enterprise'
 * @property {string} avatar_url - Profile picture URL
 * @property {boolean} is_active - Account status
 * @property {Date} created_at
 * @property {Date} updated_at
 */

const User = {
  /**
   * Find a user by their unique ID
   * @param {string} id - User UUID
   * @returns {Promise<User|null>}
   */
  async findById(id) {
    return db(TABLE)
      .where({ id, is_active: true })
      .first();
  },

  /**
   * Find a user by email address
   * @param {string} email
   * @returns {Promise<User|null>}
   */
  async findByEmail(email) {
    return db(TABLE)
      .where({ email: email.toLowerCase().trim() })
      .first();
  },

  /**
   * Get all users with pagination
   * @param {Object} options
   * @param {number} options.page
   * @param {number} options.limit
   * @returns {Promise<{users: User[], total: number}>}
   */
  async findAll({ page = 1, limit = 20 } = {}) {
    const offset = (page - 1) * limit;

    const [users, [{ count: total }]] = await Promise.all([
      db(TABLE)
        .select('id', 'email', 'name', 'role', 'plan', 'avatar_url', 'created_at')
        .where({ is_active: true })
        .orderBy('created_at', 'desc')
        .offset(offset)
        .limit(limit),
      db(TABLE).where({ is_active: true }).count('id'),
    ]);

    return { users, total: parseInt(total, 10) };
  },

  /**
   * Create a new user account
   * @param {Object} userData
   * @returns {Promise<User>}
   */
  async create({ email, password, name }) {
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const [user] = await db(TABLE)
      .insert({
        email: email.toLowerCase().trim(),
        password_hash: passwordHash,
        name: name.trim(),
        role: 'user',
        plan: 'free',
        is_active: true,
      })
      .returning(['id', 'email', 'name', 'role', 'plan', 'created_at']);

    return user;
  },

  /**
   * Update user profile fields
   * @param {string} id
   * @param {Object} updates
   * @returns {Promise<User>}
   */
  async update(id, updates) {
    const allowedFields = ['name', 'avatar_url', 'plan'];
    const sanitized = {};

    for (const [key, value] of Object.entries(updates)) {
      if (allowedFields.includes(key) && value !== undefined) {
        sanitized[key] = typeof value === 'string' ? value.trim() : value;
      }
    }

    sanitized.updated_at = new Date();

    const [user] = await db(TABLE)
      .where({ id })
      .update(sanitized)
      .returning(['id', 'email', 'name', 'role', 'plan', 'avatar_url', 'updated_at']);

    return user;
  },

  /**
   * Verify a password against the stored hash
   * @param {string} password - Plain text password
   * @param {string} hash - Stored bcrypt hash
   * @returns {Promise<boolean>}
   */
  async verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
  },

  /**
   * Soft-delete a user account
   * @param {string} id
   * @returns {Promise<void>}
   */
  async deactivate(id) {
    await db(TABLE)
      .where({ id })
      .update({ is_active: false, updated_at: new Date() });
  },
};

module.exports = User;

