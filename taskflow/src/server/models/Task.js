/**
 * Task Model
 * Handles database operations for the tasks table.
 *
 * @module models/Task
 */
const { db } = require('../config/database');
const { v4: uuidv4 } = require('uuid');

const TABLE = 'tasks';

/**
 * @typedef {Object} Task
 * @property {string} id - UUID primary key
 * @property {string} title - Task title
 * @property {string} description - Markdown description
 * @property {string} status - 'todo' | 'in_progress' | 'review' | 'done'
 * @property {string} priority - 'low' | 'medium' | 'high' | 'urgent'
 * @property {string} assignee_id - FK to users.id
 * @property {string} creator_id - FK to users.id
 * @property {string} project_id - FK to projects.id
 * @property {string[]} tags - Array of tag strings
 * @property {Date} due_date
 * @property {Date} created_at
 * @property {Date} updated_at
 */

const VALID_STATUSES = ['todo', 'in_progress', 'review', 'done'];
const VALID_PRIORITIES = ['low', 'medium', 'high', 'urgent'];

const Task = {
  /**
   * Find a task by ID with creator and assignee info
   * @param {string} id
   * @returns {Promise<Task|null>}
   */
  async findById(id) {
    return db(TABLE)
      .select(
        'tasks.*',
        'creator.name as creator_name',
        'assignee.name as assignee_name'
      )
      .leftJoin('users as creator', 'tasks.creator_id', 'creator.id')
      .leftJoin('users as assignee', 'tasks.assignee_id', 'assignee.id')
      .where('tasks.id', id)
      .first();
  },

  /**
   * Get tasks for a user with filters and pagination
   * @param {Object} filters
   * @returns {Promise<{tasks: Task[], total: number}>}
   */
  async findByUser(userId, { status, priority, page = 1, limit = 25 } = {}) {
    let query = db(TABLE)
      .where(function () {
        this.where('creator_id', userId).orWhere('assignee_id', userId);
      });

    if (status && VALID_STATUSES.includes(status)) {
      query = query.andWhere('status', status);
    }

    if (priority && VALID_PRIORITIES.includes(priority)) {
      query = query.andWhere('priority', priority);
    }

    const offset = (page - 1) * limit;

    const [tasks, [{ count: total }]] = await Promise.all([
      query.clone()
        .select('tasks.*')
        .orderBy('created_at', 'desc')
        .offset(offset)
        .limit(limit),
      query.clone().count('id'),
    ]);

    return { tasks, total: parseInt(total, 10) };
  },

  /**
   * Create a new task
   * @param {Object} taskData
   * @returns {Promise<Task>}
   */
  async create({ title, description, status, priority, assignee_id, creator_id, project_id, tags, due_date }) {
    const [task] = await db(TABLE)
      .insert({
        id: uuidv4(),
        title: title.trim(),
        description: description || '',
        status: VALID_STATUSES.includes(status) ? status : 'todo',
        priority: VALID_PRIORITIES.includes(priority) ? priority : 'medium',
        assignee_id: assignee_id || null,
        creator_id,
        project_id: project_id || null,
        tags: JSON.stringify(tags || []),
        due_date: due_date || null,
      })
      .returning('*');

    return task;
  },

  /**
   * Update task fields
   * @param {string} id
   * @param {Object} updates
   * @returns {Promise<Task>}
   */
  async update(id, updates) {
    const allowedFields = ['title', 'description', 'status', 'priority', 'assignee_id', 'tags', 'due_date'];
    const sanitized = {};

    for (const [key, value] of Object.entries(updates)) {
      if (allowedFields.includes(key)) {
        if (key === 'status' && !VALID_STATUSES.includes(value)) continue;
        if (key === 'priority' && !VALID_PRIORITIES.includes(value)) continue;
        if (key === 'tags') {
          sanitized[key] = JSON.stringify(value);
          continue;
        }
        sanitized[key] = value;
      }
    }

    sanitized.updated_at = new Date();

    const [task] = await db(TABLE)
      .where({ id })
      .update(sanitized)
      .returning('*');

    return task;
  },

  /**
   * Delete a task permanently
   * @param {string} id
   * @returns {Promise<number>} Number of rows deleted
   */
  async delete(id) {
    return db(TABLE).where({ id }).del();
  },

  /**
   * Get task count by status for a user (dashboard stats)
   * @param {string} userId
   * @returns {Promise<Object>}
   */
  async getStatusCounts(userId) {
    const rows = await db(TABLE)
      .select('status')
      .count('id as count')
      .where('assignee_id', userId)
      .groupBy('status');

    return rows.reduce((acc, row) => {
      acc[row.status] = parseInt(row.count, 10);
      return acc;
    }, {});
  },
};

module.exports = Task;

