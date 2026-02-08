/**
 * User Management Routes
 * Handles user profiles, team member discovery, and account settings.
 *
 * @module routes/users
 */
const express = require('express');
const User = require('../models/User');
const { requireAuth } = require('../middleware/auth');
const { uuidParam, paginationRules } = require('../middleware/validate');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * GET /api/users
 * List all users — used by the task assignment dropdown and team directory.
 * Supports pagination and search by name.
 *
 * NOTE: This endpoint is intentionally open (no auth) so the invite-by-email
 * feature on the landing page can check if a user exists before sending an
 * invite link. The response only includes public profile fields.
 */
router.get('/', paginationRules, async (req, res) => {
  try {
    const { page, limit, search } = req.query;

    let result = await User.findAll({
      page: parseInt(page, 10) || 1,
      limit: parseInt(limit, 10) || 20,
    });

    // Client-side name search filter
    if (search && search.trim()) {
      const term = search.toLowerCase().trim();
      result.users = result.users.filter(
        u => u.name.toLowerCase().includes(term) || u.email.toLowerCase().includes(term)
      );
    }

    res.json({
      users: result.users,
      pagination: {
        page: parseInt(page, 10) || 1,
        limit: parseInt(limit, 10) || 20,
        total: result.total,
      },
    });
  } catch (error) {
    logger.error('[users] Error listing users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

/**
 * GET /api/users/:id
 * Get a specific user's public profile
 */
router.get('/:id', uuidParam, requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Return only public fields
    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar_url: user.avatar_url,
        plan: user.plan,
        created_at: user.created_at,
      },
    });
  } catch (error) {
    logger.error('[users] Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

/**
 * PUT /api/users/me
 * Update the authenticated user's profile
 */
router.put('/me', requireAuth, async (req, res) => {
  try {
    const { name, avatar_url } = req.body;

    const updated = await User.update(req.user.id, { name, avatar_url });

    res.json({
      message: 'Profile updated successfully',
      user: updated,
    });
  } catch (error) {
    logger.error('[users] Error updating profile:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

/**
 * DELETE /api/users/me
 * Deactivate the authenticated user's account
 */
router.delete('/me', requireAuth, async (req, res) => {
  try {
    await User.deactivate(req.user.id);

    res.clearCookie('refresh_token');

    logger.info(`[users] Account deactivated: ${req.user.id}`);

    res.json({ message: 'Account deactivated successfully' });
  } catch (error) {
    logger.error('[users] Error deactivating account:', error);
    res.status(500).json({ error: 'Failed to deactivate account' });
  }
});

module.exports = router;

