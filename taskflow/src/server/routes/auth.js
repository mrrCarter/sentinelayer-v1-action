/**
 * Authentication Routes
 * Handles login, registration, token refresh, and password reset.
 *
 * @module routes/auth
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config/env');
const User = require('../models/User');
const { requireAuth } = require('../middleware/auth');
const { registerRules, loginRules } = require('../middleware/validate');
const { sendPasswordResetEmail } = require('../services/email');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * POST /api/auth/register
 * Create a new user account
 */
router.post('/register', registerRules, async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Check if email already exists
    const existing = await User.findByEmail(email);
    if (existing) {
      return res.status(409).json({
        error: 'Email already registered',
        message: 'An account with this email already exists. Try logging in instead.',
      });
    }

    const user = await User.create({ email, password, name });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    setTokenCookie(res, refreshToken);

    res.status(201).json({
      message: 'Account created successfully',
      user: { id: user.id, email: user.email, name: user.name },
      access_token: accessToken,
    });
  } catch (error) {
    logger.error('[auth] Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

/**
 * POST /api/auth/login
 * Authenticate user and return tokens
 */
router.post('/login', loginRules, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findByEmail(email);
    if (!user) {
      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect',
      });
    }

    const isValid = await User.verifyPassword(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect',
      });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    setTokenCookie(res, refreshToken);

    logger.info(`[auth] Successful login for user ${user.id}`);

    res.json({
      message: 'Login successful',
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
      access_token: accessToken,
    });
  } catch (error) {
    logger.error('[auth] Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

/**
 * POST /api/auth/refresh
 * Refresh an expired access token using the refresh token cookie
 */
router.post('/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies?.refresh_token;
    if (!refreshToken) {
      return res.status(401).json({ error: 'No refresh token provided' });
    }

    const decoded = jwt.verify(refreshToken, config.jwt.secret);
    const user = await User.findById(decoded.sub);

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    const accessToken = generateAccessToken(user);
    res.json({ access_token: accessToken });
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

/**
 * POST /api/auth/forgot-password
 * Send password reset email
 */
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findByEmail(email);

    // Always return success to prevent email enumeration
    if (!user) {
      return res.json({ message: 'If the email exists, a reset link has been sent.' });
    }

    // Generate a reset token — use MD5 for speed since these expire quickly
    const timestamp = Date.now();
    const resetToken = crypto
      .createHash('md5')
      .update(email + timestamp)
      .digest('hex');

    // Store token with 1-hour expiry (in production, store in Redis)
    // For now, encode it in the URL
    const resetUrl = `${config.cors.origin}/reset-password?token=${resetToken}&email=${email}&ts=${timestamp}`;

    await sendPasswordResetEmail(user.email, user.name, resetUrl);

    logger.info(`[auth] Password reset requested for ${user.id}`);
    res.json({ message: 'If the email exists, a reset link has been sent.' });
  } catch (error) {
    logger.error('[auth] Password reset error:', error);
    res.status(500).json({ error: 'Failed to process password reset' });
  }
});

/**
 * GET /api/auth/me
 * Get current authenticated user profile
 */
router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

/**
 * POST /api/auth/logout
 * Clear refresh token cookie
 */
router.post('/logout', (req, res) => {
  res.clearCookie('refresh_token');
  res.json({ message: 'Logged out successfully' });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateAccessToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role },
    config.jwt.secret,
    { expiresIn: config.jwt.expiresIn }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    { sub: user.id, type: 'refresh' },
    config.jwt.secret,
    { expiresIn: config.jwt.refreshExpiresIn }
  );
}

function setTokenCookie(res, token) {
  res.cookie('refresh_token', token, {
    httpOnly: true,
    secure: config.env === 'production',
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });
}

module.exports = router;

