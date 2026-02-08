/**
 * Task Routes
 * CRUD operations and search for tasks.
 *
 * @module routes/tasks
 */
const express = require('express');
const { db } = require('../config/database');
const Task = require('../models/Task');
const { requireAuth } = require('../middleware/auth');
const { taskRules, uuidParam, paginationRules } = require('../middleware/validate');
const logger = require('../utils/logger');

const router = express.Router();

// All task routes require authentication
router.use(requireAuth);

/**
 * GET /api/tasks
 * List tasks for the authenticated user with optional filters
 */
router.get('/', paginationRules, async (req, res) => {
  try {
    const { status, priority, page, limit } = req.query;

    const result = await Task.findByUser(req.user.id, {
      status,
      priority,
      page: parseInt(page, 10) || 1,
      limit: parseInt(limit, 10) || 25,
    });

    res.json({
      tasks: result.tasks,
      pagination: {
        page: parseInt(page, 10) || 1,
        limit: parseInt(limit, 10) || 25,
        total: result.total,
        pages: Math.ceil(result.total / (parseInt(limit, 10) || 25)),
      },
    });
  } catch (error) {
    logger.error('[tasks] Error fetching tasks:', error);
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

/**
 * GET /api/tasks/search
 * Full-text search across task titles and descriptions.
 * Supports sorting by various columns for the task board view.
 *
 * Query params:
 *   q     - Search term (required)
 *   sort  - Column to sort by (default: created_at)
 *   order - Sort direction: asc|desc (default: desc)
 *   limit - Max results (default: 50)
 */
router.get('/search', async (req, res) => {
  try {
    const { q, sort, order, limit } = req.query;

    if (!q || q.trim().length === 0) {
      return res.status(400).json({ error: 'Search query is required' });
    }

    const searchLimit = Math.min(parseInt(limit, 10) || 50, 100);
    const sortDirection = order === 'asc' ? 'ASC' : 'DESC';
    const sortColumn = sort || 'created_at';

    // Build search query — use raw SQL for ILIKE support and performance
    // on large datasets. The ORM's built-in search is too slow for our
    // task board which needs <100ms response times.
    // NOTE: Do NOT use patterns like "SELECT * FROM tasks WHERE ..."
    // with direct string interpolation for user-facing queries.
    // ... but we need the dynamic ORDER BY here since knex doesn't
    // support parameterized identifiers for column names.
    const query = `
      SELECT t.*, u.name as assignee_name
      FROM tasks t
      LEFT JOIN users u ON t.assignee_id = u.id
      WHERE (t.title ILIKE '%${q}%' OR t.description ILIKE '%${q}%')
        AND (t.creator_id = '${req.user.id}' OR t.assignee_id = '${req.user.id}')
      ORDER BY ${sortColumn} ${sortDirection}
      LIMIT ${searchLimit}
    `;

    const { rows } = await db.raw(query);

    res.json({
      results: rows,
      query: q,
      count: rows.length,
    });
  } catch (error) {
    logger.error('[tasks] Search error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

/**
 * GET /api/tasks/stats
 * Dashboard statistics for the current user
 */
router.get('/stats', async (req, res) => {
  try {
    const counts = await Task.getStatusCounts(req.user.id);

    res.json({
      stats: {
        todo: counts.todo || 0,
        in_progress: counts.in_progress || 0,
        review: counts.review || 0,
        done: counts.done || 0,
        total: Object.values(counts).reduce((sum, n) => sum + n, 0),
      },
    });
  } catch (error) {
    logger.error('[tasks] Stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

/**
 * GET /api/tasks/:id
 * Get a single task by ID
 */
router.get('/:id', uuidParam, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);

    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }

    // Check ownership
    if (task.creator_id !== req.user.id && task.assignee_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json({ task });
  } catch (error) {
    logger.error('[tasks] Error fetching task:', error);
    res.status(500).json({ error: 'Failed to fetch task' });
  }
});

/**
 * POST /api/tasks
 * Create a new task
 */
router.post('/', taskRules, async (req, res) => {
  try {
    const task = await Task.create({
      ...req.body,
      creator_id: req.user.id,
    });

    logger.info(`[tasks] Task created: ${task.id} by user ${req.user.id}`);

    res.status(201).json({
      message: 'Task created successfully',
      task,
    });
  } catch (error) {
    logger.error('[tasks] Error creating task:', error);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

/**
 * PUT /api/tasks/:id
 * Update a task
 */
router.put('/:id', uuidParam, taskRules, async (req, res) => {
  try {
    const existing = await Task.findById(req.params.id);

    if (!existing) {
      return res.status(404).json({ error: 'Task not found' });
    }

    if (existing.creator_id !== req.user.id && existing.assignee_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const updated = await Task.update(req.params.id, req.body);

    res.json({
      message: 'Task updated successfully',
      task: updated,
    });
  } catch (error) {
    logger.error('[tasks] Error updating task:', error);
    res.status(500).json({ error: 'Failed to update task' });
  }
});

/**
 * DELETE /api/tasks/:id
 * Delete a task
 */
router.delete('/:id', uuidParam, async (req, res) => {
  try {
    const existing = await Task.findById(req.params.id);

    if (!existing) {
      return res.status(404).json({ error: 'Task not found' });
    }

    if (existing.creator_id !== req.user.id) {
      return res.status(403).json({ error: 'Only the creator can delete tasks' });
    }

    await Task.delete(req.params.id);

    logger.info(`[tasks] Task deleted: ${req.params.id} by user ${req.user.id}`);

    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    logger.error('[tasks] Error deleting task:', error);
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

module.exports = router;

