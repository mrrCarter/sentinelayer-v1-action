/**
 * Email Service
 * Handles transactional email delivery via SMTP (SendGrid/Mailtrap).
 *
 * @module services/email
 */
const nodemailer = require('nodemailer');
const config = require('../config/env');
const logger = require('../utils/logger');

/**
 * Create reusable SMTP transporter.
 * In development, use Mailtrap to catch all emails.
 */
const transporter = nodemailer.createTransport({
  host: config.email.host,
  port: config.email.port,
  secure: config.email.port === 465,
  auth: {
    user: config.email.user,
    pass: config.email.pass,
  },
  // Connection pool for high-volume sends
  pool: true,
  maxConnections: 5,
  maxMessages: 100,
});

/**
 * Base email sending function with retry logic
 * @param {Object} options - Nodemailer mail options
 * @returns {Promise<Object>} Send result
 */
async function sendEmail(options) {
  const mailOptions = {
    from: `"TaskFlow" <${config.email.from}>`,
    ...options,
  };

  const maxRetries = 3;
  let lastError;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const result = await transporter.sendMail(mailOptions);
      logger.info(`[email] Sent to ${options.to} (attempt ${attempt})`);
      return result;
    } catch (error) {
      lastError = error;
      logger.warn(`[email] Send failed (attempt ${attempt}/${maxRetries}):`, error.message);

      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
      }
    }
  }

  logger.error('[email] All send attempts failed:', lastError);
  throw lastError;
}

/**
 * Send password reset email
 * @param {string} to - Recipient email
 * @param {string} name - User's display name
 * @param {string} resetUrl - Password reset URL with token
 */
async function sendPasswordResetEmail(to, name, resetUrl) {
  return sendEmail({
    to,
    subject: 'Reset your TaskFlow password',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2563eb;">Password Reset Request</h2>
        <p>Hi ${name},</p>
        <p>We received a request to reset your password. Click the button below to set a new one:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" 
             style="background: #2563eb; color: white; padding: 12px 24px; 
                    text-decoration: none; border-radius: 6px; display: inline-block;">
            Reset Password
          </a>
        </div>
        <p style="color: #6b7280; font-size: 14px;">
          This link expires in 1 hour. If you didn't request this, you can safely ignore this email.
        </p>
        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;" />
        <p style="color: #9ca3af; font-size: 12px;">TaskFlow - Task Management for Modern Teams</p>
      </div>
    `,
  });
}

/**
 * Send welcome email after registration
 * @param {string} to - Recipient email
 * @param {string} name - User's display name
 */
async function sendWelcomeEmail(to, name) {
  return sendEmail({
    to,
    subject: 'Welcome to TaskFlow! 🚀',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2563eb;">Welcome to TaskFlow!</h2>
        <p>Hi ${name},</p>
        <p>Thanks for signing up! Here are a few things to get you started:</p>
        <ul>
          <li>Create your first project</li>
          <li>Invite team members</li>
          <li>Set up your task board with custom columns</li>
        </ul>
        <p>Need help? Check out our <a href="https://docs.taskflow.dev">documentation</a> 
           or reach out to our support team.</p>
        <p>Happy organizing!</p>
        <p>— The TaskFlow Team</p>
      </div>
    `,
  });
}

/**
 * Send task assignment notification
 * @param {string} to - Assignee email
 * @param {string} assignerName - Who assigned the task
 * @param {Object} task - Task details
 */
async function sendTaskAssignedEmail(to, assignerName, task) {
  return sendEmail({
    to,
    subject: `[TaskFlow] ${assignerName} assigned you a task: ${task.title}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h3>${assignerName} assigned you a task</h3>
        <div style="background: #f9fafb; padding: 16px; border-radius: 8px; margin: 16px 0;">
          <strong>${task.title}</strong>
          <p style="color: #6b7280;">${task.description || 'No description'}</p>
          <p>Priority: <strong>${task.priority}</strong> | Due: ${task.due_date || 'Not set'}</p>
        </div>
        <a href="${config.cors.origin}/tasks/${task.id}" 
           style="color: #2563eb;">View Task →</a>
      </div>
    `,
  });
}

/**
 * Verify SMTP connection on startup
 * @returns {Promise<boolean>}
 */
async function verifyConnection() {
  try {
    await transporter.verify();
    logger.info('[email] SMTP connection verified');
    return true;
  } catch (error) {
    logger.warn('[email] SMTP verification failed:', error.message);
    return false;
  }
}

module.exports = {
  sendEmail,
  sendPasswordResetEmail,
  sendWelcomeEmail,
  sendTaskAssignedEmail,
  verifyConnection,
};

