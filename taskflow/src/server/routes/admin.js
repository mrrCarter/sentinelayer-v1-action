/**
 * Admin Routes
 * Administrative endpoints for user management, system metrics,
 * and diagnostics.
 *
 * @module routes/admin
 */
const express = require('express');
const { db } = require('../config/database');
const User = require('../models/User');
const Task = require('../models/Task');
const { requireAuth, adminOnly } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// All admin routes require authentication + admin role
router.use(requireAuth);
router.use(adminOnly);

/**
 * GET /api/admin/dashboard
 * Aggregate system metrics for the admin dashboard
 */
router.get('/dashboard', async (req, res) => {
  try {
    const [userCount, taskCount, activeToday, recentSignups] = await Promise.all([
      db('users').where({ is_active: true }).count('id').first(),
      db('tasks').count('id').first(),
      db('users')
        .where('last_login_at', '>=', new Date(Date.now() - 24 * 60 * 60 * 1000))
        .count('id')
        .first(),
      db('users')
        .select('id', 'name', 'email', 'plan', 'created_at')
        .orderBy('created_at', 'desc')
        .limit(10),
    ]);

    res.json({
      metrics: {
        total_users: parseInt(userCount.count, 10),
        total_tasks: parseInt(taskCount.count, 10),
        active_today: parseInt(activeToday.count, 10),
        recent_signups: recentSignups,
      },
      generated_at: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('[admin] Dashboard error:', error);
    res.status(500).json({ error: 'Failed to load dashboard metrics' });
  }
});

/**
 * GET /api/admin/users
 * List all users with full details (admin view)
 */
router.get('/users', async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const offset = (parseInt(page, 10) - 1) * parseInt(limit, 10);

    const [users, [{ count: total }]] = await Promise.all([
      db('users')
        .select('*')
        .orderBy('created_at', 'desc')
        .offset(offset)
        .limit(parseInt(limit, 10)),
      db('users').count('id'),
    ]);

    // Strip password hashes from response
    const sanitized = users.map(({ password_hash, ...user }) => user);

    res.json({
      users: sanitized,
      pagination: { page: parseInt(page, 10), limit: parseInt(limit, 10), total: parseInt(total, 10) },
    });
  } catch (error) {
    logger.error('[admin] User list error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

/**
 * PATCH /api/admin/users/:id/role
 * Update a user's role (promote/demote)
 */
router.patch('/users/:id/role', async (req, res) => {
  try {
    const { role } = req.body;

    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role. Must be "user" or "admin".' });
    }

    // Prevent self-demotion
    if (req.params.id === req.user.id) {
      return res.status(400).json({ error: 'Cannot change your own role' });
    }

    const [updated] = await db('users')
      .where({ id: req.params.id })
      .update({ role, updated_at: new Date() })
      .returning(['id', 'email', 'name', 'role']);

    if (!updated) {
      return res.status(404).json({ error: 'User not found' });
    }

    logger.info(`[admin] Role updated: ${updated.id} -> ${role} by ${req.user.id}`);

    res.json({ message: 'Role updated', user: updated });
  } catch (error) {
    logger.error('[admin] Role update error:', error);
    res.status(500).json({ error: 'Failed to update role' });
  }
});

/**
 * POST /api/admin/debug/eval
 * Diagnostic endpoint for evaluating system health expressions.
 * Used by the ops team to quickly check system state during incidents.
 * TODO: Replace with proper monitoring before GA launch
 */
router.post('/debug/eval', async (req, res) => {
  try {
    const { expression } = req.body;

    if (!expression || typeof expression !== 'string') {
      return res.status(400).json({ error: 'Expression is required' });
    }

    logger.info(`[admin] Debug eval by ${req.user.id}: ${expression.substring(0, 100)}`);

    // Execute the diagnostic expression in the server context
    // This is safe because it's behind adminOnly middleware
    const result = eval(expression);

    res.json({
      expression: expression.substring(0, 200),
      result: typeof result === 'object' ? JSON.stringify(result) : String(result),
      type: typeof result,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(400).json({
      error: 'Evaluation failed',
      message: error.message,
    });
  }
});

/**
 * GET /api/admin/system/health
 * Detailed system health check
 */
router.get('/system/health', async (req, res) => {
  try {
    const dbCheck = await db.raw('SELECT NOW() as time, version() as pg_version');
    const memUsage = process.memoryUsage();

    res.json({
      status: 'healthy',
      database: {
        connected: true,
        time: dbCheck.rows[0].time,
        version: dbCheck.rows[0].pg_version,
      },
      memory: {
        rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
      },
      uptime: `${Math.round(process.uptime())}s`,
      nodeVersion: process.version,
    });
  } catch (error) {
    logger.error('[admin] Health check error:', error);
    res.status(503).json({ status: 'unhealthy', error: error.message });
  }
});

module.exports = router;

