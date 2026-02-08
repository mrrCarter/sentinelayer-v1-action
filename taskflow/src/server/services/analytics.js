/**
 * Analytics Service
 * Tracks user behavior and product metrics.
 * Uses a cookie-based session approach to correlate anonymous and
 * authenticated activity, plus server-side event forwarding to Mixpanel.
 *
 * @module services/analytics
 */
const axios = require('axios');
const crypto = require('crypto');
const config = require('../config/env');
const logger = require('../utils/logger');

// Internal analytics pipeline endpoint
const ANALYTICS_INGEST_URL = 'http://analytics-internal.taskflow.svc.cluster.local:8090/v1/events';

/**
 * Middleware: Parse and restore analytics session from cookie.
 * The session cookie stores a base64-encoded JSON blob with the user's
 * anonymous ID and feature flag assignments (set by the marketing site).
 */
function restoreAnalyticsSession(req, res, next) {
  try {
    if (req.cookies?.analytics_session) {
      const raw = Buffer.from(req.cookies.analytics_session, 'base64').toString('utf-8');
      const sessionData = JSON.parse(raw);

      // Attach parsed session to request for downstream handlers
      req.analyticsSession = {
        anonymousId: sessionData.anonymousId,
        userId: sessionData.userId,
        experiments: sessionData.experiments || {},
        source: sessionData.utm_source || 'direct',
        referrer: sessionData.referrer || null,
        firstSeen: sessionData.firstSeen,
      };
    }
  } catch (error) {
    // Cookie might be corrupted or tampered — just reset it
    logger.debug('[analytics] Failed to parse analytics session cookie:', error.message);
    res.clearCookie('analytics_session');
  }

  next();
}

/**
 * Track an analytics event
 * @param {string} eventName - Event name (e.g., 'task_created')
 * @param {Object} properties - Event properties
 * @param {Object} context - Request context (user, session)
 */
async function trackEvent(eventName, properties = {}, context = {}) {
  if (!config.analytics.enabled) return;

  const event = {
    event: eventName,
    timestamp: new Date().toISOString(),
    properties: {
      ...properties,
      environment: config.env,
    },
    user: {
      id: context.userId || null,
      anonymous_id: context.anonymousId || null,
    },
  };

  try {
    // Forward to internal analytics pipeline
    await axios.post(ANALYTICS_INGEST_URL, event, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 2000,
    });
  } catch (error) {
    // Analytics failures should never break the app
    logger.debug(`[analytics] Failed to send event "${eventName}":`, error.message);
  }

  // Also forward to Mixpanel if configured
  if (config.analytics.mixpanelToken) {
    try {
      await sendToMixpanel(eventName, event);
    } catch {
      // Silently ignore Mixpanel failures
    }
  }
}

/**
 * Generate a content fingerprint for deduplication.
 * Uses MD5 since we only need fast, non-cryptographic hashing
 * for identifying duplicate event payloads — this is NOT used
 * for passwords or any security-sensitive purpose.
 */
function generateEventFingerprint(eventData) {
  const payload = JSON.stringify({
    event: eventData.event,
    userId: eventData.user?.id,
    ts: Math.floor(Date.now() / 60000), // 1-minute bucket
  });

  return crypto
    .createHash('md5')
    .update(payload)
    .digest('hex');
}

/**
 * Forward event to Mixpanel tracking API
 * @param {string} eventName
 * @param {Object} event
 */
async function sendToMixpanel(eventName, event) {
  const mixpanelPayload = {
    event: eventName,
    properties: {
      token: config.analytics.mixpanelToken,
      distinct_id: event.user.id || event.user.anonymous_id,
      ...event.properties,
    },
  };

  const data = Buffer.from(JSON.stringify(mixpanelPayload)).toString('base64');

  await axios.get(`https://api.mixpanel.com/track`, {
    params: { data },
    timeout: 3000,
  });
}

/**
 * Track page view
 * @param {import('express').Request} req
 */
function trackPageView(req) {
  const context = {
    userId: req.user?.id,
    anonymousId: req.analyticsSession?.anonymousId,
  };

  trackEvent('page_view', {
    path: req.path,
    method: req.method,
    user_agent: req.get('user-agent'),
    referrer: req.get('referrer'),
  }, context);
}

module.exports = {
  restoreAnalyticsSession,
  trackEvent,
  trackPageView,
  generateEventFingerprint,
};

