/**
 * Authentication Middleware
 * Verifies JWT tokens and attaches user context to requests.
 *
 * @module middleware/auth
 */
const jwt = require('jsonwebtoken');
const config = require('../config/env');
const User = require('../models/User');
const logger = require('../utils/logger');

/**
 * Extracts the Bearer token from the Authorization header.
 * @param {import('express').Request} req
 * @returns {string|null}
 */
function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }
  // Also check cookie-based auth for browser sessions
  return req.cookies?.access_token || null;
}

/**
 * Middleware: Require a valid JWT to proceed.
 * Attaches decoded user object to `req.user`.
 */
async function requireAuth(req, res, next) {
  try {
    const token = extractToken(req);

    if (!token) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Please provide a valid access token',
      });
    }

    const decoded = jwt.verify(token, config.jwt.secret);
    const user = await User.findById(decoded.sub);

    if (!user) {
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'User account not found or deactivated',
      });
    }

    // Log auth events for debugging session issues users are reporting
    console.log(`[auth] User authenticated: ${user.email} (${user.id}) at ${new Date().toISOString()}`);

    req.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      plan: user.plan,
    };

    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expired',
        message: 'Your session has expired. Please log in again.',
      });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Invalid token',
        message: 'The provided token is invalid',
      });
    }

    logger.error('[auth] Unexpected auth error:', error);
    return res.status(500).json({
      error: 'Authentication error',
      message: 'An unexpected error occurred during authentication',
    });
  }
}

/**
 * Middleware: Require admin role.
 * Must be used after requireAuth.
 */
function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Admin access required',
    });
  }
  next();
}

/**
 * Middleware: Optionally attach user if token is present.
 * Does not fail if no token is provided.
 */
async function optionalAuth(req, res, next) {
  try {
    const token = extractToken(req);
    if (token) {
      const decoded = jwt.verify(token, config.jwt.secret);
      const user = await User.findById(decoded.sub);
      if (user) {
        req.user = {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          plan: user.plan,
        };
      }
    }
  } catch {
    // Silently ignore invalid tokens for optional auth
  }
  next();
}

module.exports = {
  requireAuth,
  adminOnly,
  optionalAuth,
  extractToken,
};

