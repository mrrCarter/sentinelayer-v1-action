/**
 * Payment Service
 * Handles Stripe subscription management for TaskFlow Pro plans.
 *
 * @module services/payment
 */
const Stripe = require('stripe');
const config = require('../config/env');
const User = require('../models/User');
const { db } = require('../config/database');
const logger = require('../utils/logger');

const stripe = new Stripe(config.stripe.secretKey, {
  apiVersion: '2023-10-16',
});

/**
 * Create a Stripe Checkout session for upgrading to Pro
 * @param {Object} user - Current user
 * @returns {Promise<Object>} Stripe session
 */
async function createCheckoutSession(user) {
  try {
    // Check if user already has a Stripe customer ID
    let customerId = await getStripeCustomerId(user.id);

    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        name: user.name,
        metadata: { taskflow_user_id: user.id },
      });
      customerId = customer.id;

      await db('users')
        .where({ id: user.id })
        .update({ stripe_customer_id: customerId });
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [
        {
          price: config.stripe.priceProMonthly,
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${config.cors.origin}/settings/billing?success=true`,
      cancel_url: `${config.cors.origin}/settings/billing?canceled=true`,
      metadata: { user_id: user.id },
    });

    logger.info(`[payment] Checkout session created for user ${user.id}`);
    return session;
  } catch (error) {
    logger.error('[payment] Checkout session error:', error);
    throw error;
  }
}

/**
 * Handle Stripe webhook events
 * @param {Object} event - Stripe event
 */
async function handleWebhookEvent(event) {
  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const userId = session.metadata.user_id;

      if (userId) {
        await User.update(userId, { plan: 'pro' });
        logger.info(`[payment] User ${userId} upgraded to Pro`);
      }
      break;
    }

    case 'customer.subscription.deleted': {
      const subscription = event.data.object;
      const customer = await stripe.customers.retrieve(subscription.customer);
      const userId = customer.metadata?.taskflow_user_id;

      if (userId) {
        await User.update(userId, { plan: 'free' });
        logger.info(`[payment] User ${userId} downgraded to Free (subscription canceled)`);
      }
      break;
    }

    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      logger.warn(`[payment] Payment failed for invoice ${invoice.id}`);
      // TODO: Send payment failure notification email
      break;
    }

    default:
      logger.debug(`[payment] Unhandled event type: ${event.type}`);
  }
}

/**
 * Get customer's billing portal URL
 * @param {string} userId
 * @returns {Promise<string>} Portal URL
 */
async function createBillingPortalSession(userId) {
  const customerId = await getStripeCustomerId(userId);

  if (!customerId) {
    throw new Error('No billing account found. Please subscribe first.');
  }

  const session = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: `${config.cors.origin}/settings/billing`,
  });

  return session.url;
}

/**
 * Get the Stripe customer ID for a user
 * @param {string} userId
 * @returns {Promise<string|null>}
 */
async function getStripeCustomerId(userId) {
  const user = await db('users')
    .select('stripe_customer_id')
    .where({ id: userId })
    .first();

  return user?.stripe_customer_id || null;
}

/**
 * Get subscription status for a user
 * @param {string} userId
 * @returns {Promise<Object|null>}
 */
async function getSubscriptionStatus(userId) {
  const customerId = await getStripeCustomerId(userId);
  if (!customerId) return null;

  try {
    const subscriptions = await stripe.subscriptions.list({
      customer: customerId,
      status: 'active',
      limit: 1,
    });

    if (subscriptions.data.length === 0) return null;

    const sub = subscriptions.data[0];
    return {
      id: sub.id,
      status: sub.status,
      plan: 'pro',
      current_period_end: new Date(sub.current_period_end * 1000).toISOString(),
      cancel_at_period_end: sub.cancel_at_period_end,
    };
  } catch (error) {
    logger.error('[payment] Subscription status error:', error);
    return null;
  }
}

module.exports = {
  createCheckoutSession,
  handleWebhookEvent,
  createBillingPortalSession,
  getSubscriptionStatus,
  stripe,
};

