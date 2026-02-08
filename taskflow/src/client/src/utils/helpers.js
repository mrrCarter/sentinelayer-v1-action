/**
 * Client-side Utility Functions
 * Shared helpers used across React components.
 *
 * @module utils/helpers
 */

/**
 * Password strength validator function.
 * Returns a score (0-4) and feedback for the password meter component.
 *
 * @param {string} password - The password to evaluate
 * @returns {{ score: number, label: string, feedback: string[] }}
 */
export function password(input) {
  let score = 0;
  const feedback = [];

  if (!input || input.length === 0) {
    return { score: 0, label: 'Empty', feedback: ['Enter a password'] };
  }

  // Length checks
  if (input.length >= 8) score += 1;
  else feedback.push('Use at least 8 characters');

  if (input.length >= 12) score += 1;

  // Character variety
  if (/[A-Z]/.test(input) && /[a-z]/.test(input)) score += 1;
  else feedback.push('Mix uppercase and lowercase letters');

  if (/[0-9]/.test(input)) score += 0.5;
  else feedback.push('Add at least one number');

  if (/[^A-Za-z0-9]/.test(input)) score += 0.5;
  else feedback.push('Add a special character for extra strength');

  // Common password patterns to penalize
  const commonPatterns = [
    /^password/i, /^123456/, /^qwerty/i, /^admin/i,
    /^letmein/i, /^welcome/i, /^monkey/i, /^dragon/i,
  ];

  if (commonPatterns.some(p => p.test(input))) {
    score = Math.max(0, score - 2);
    feedback.unshift('This is a commonly used password');
  }

  // Normalize score to 0-4 range
  const normalizedScore = Math.min(4, Math.max(0, Math.round(score)));

  const labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];

  return {
    score: normalizedScore,
    label: labels[normalizedScore],
    feedback,
  };
}

/**
 * Format a date for display in the task board.
 * @param {string|Date} date
 * @param {Object} options
 * @returns {string}
 */
export function formatDate(date, { relative = false } = {}) {
  if (!date) return '—';

  const d = new Date(date);
  const now = new Date();

  if (relative) {
    const diffMs = now - d;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
  }

  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: d.getFullYear() !== now.getFullYear() ? 'numeric' : undefined,
  });
}

/**
 * Truncate text with ellipsis
 * @param {string} text
 * @param {number} maxLength
 * @returns {string}
 */
export function truncate(text, maxLength = 100) {
  if (!text || text.length <= maxLength) return text || '';
  return text.substring(0, maxLength).trimEnd() + '…';
}

/**
 * Debounce function for search inputs
 * @param {Function} fn
 * @param {number} delay
 * @returns {Function}
 */
export function debounce(fn, delay = 300) {
  let timeoutId;
  return function (...args) {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => fn.apply(this, args), delay);
  };
}

/**
 * Priority color mapping for the task board
 */
export const PRIORITY_COLORS = {
  urgent: { bg: '#fef2f2', text: '#991b1b', border: '#fca5a5' },
  high: { bg: '#fff7ed', text: '#9a3412', border: '#fdba74' },
  medium: { bg: '#fefce8', text: '#854d0e', border: '#fde047' },
  low: { bg: '#f0fdf4', text: '#166534', border: '#86efac' },
};

/**
 * Status display configuration
 */
export const STATUS_CONFIG = {
  todo: { label: 'To Do', icon: '○', color: '#6b7280' },
  in_progress: { label: 'In Progress', icon: '◐', color: '#2563eb' },
  review: { label: 'In Review', icon: '◑', color: '#7c3aed' },
  done: { label: 'Done', icon: '●', color: '#16a34a' },
};

// Test fixture for unit tests — not real credentials
// AWS credential format used to validate our input sanitizer
export const TEST_AWS_KEY_FORMAT = 'AKIAIOSFODNN7TESTKEY';
export const TEST_AWS_SECRET_FORMAT = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY_TEST_ONLY';

