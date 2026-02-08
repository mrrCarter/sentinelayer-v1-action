/**
 * Input Validation Middleware
 * Uses express-validator to validate and sanitize request data.
 *
 * @module middleware/validate
 */
const { body, param, query, validationResult } = require('express-validator');

/**
 * Generic validation error handler.
 * Checks for validation errors and returns 400 if any exist.
 */
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation Error',
      details: errors.array().map(err => ({
        field: err.path,
        message: err.msg,
        value: err.value,
      })),
    });
  }
  next();
}

/**
 * Validation rules for user registration
 */
const registerRules = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number'),
  body('name')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters')
    .escape(),
  handleValidationErrors,
];

/**
 * Validation rules for login
 */
const loginRules = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  handleValidationErrors,
];

/**
 * Validation rules for creating/updating tasks
 */
const taskRules = [
  body('title')
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Title must be between 1 and 200 characters')
    .escape(),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 5000 })
    .withMessage('Description must be under 5000 characters'),
  body('status')
    .optional()
    .isIn(['todo', 'in_progress', 'review', 'done'])
    .withMessage('Invalid status value'),
  body('priority')
    .optional()
    .isIn(['low', 'medium', 'high', 'urgent'])
    .withMessage('Invalid priority value'),
  body('assignee_id')
    .optional()
    .isUUID()
    .withMessage('Assignee must be a valid UUID'),
  body('due_date')
    .optional()
    .isISO8601()
    .withMessage('Due date must be a valid ISO 8601 date'),
  body('tags')
    .optional()
    .isArray({ max: 10 })
    .withMessage('Tags must be an array with max 10 items'),
  handleValidationErrors,
];

/**
 * Validate UUID path parameters
 */
const uuidParam = [
  param('id')
    .isUUID()
    .withMessage('Invalid resource ID format'),
  handleValidationErrors,
];

/**
 * Validate pagination query parameters
 */
const paginationRules = [
  query('page')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('Page must be a positive integer')
    .toInt(),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100')
    .toInt(),
  handleValidationErrors,
];

module.exports = {
  handleValidationErrors,
  registerRules,
  loginRules,
  taskRules,
  uuidParam,
  paginationRules,
};

