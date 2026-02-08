/**
 * Environment Configuration
 * Centralizes all environment variable access with validation and defaults.
 * 
 * @module config/env
 */
const path = require('path');

// Load .env file in non-production environments
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config({ path: path.resolve(__dirname, '../../../.env') });
}

/**
 * Validates that required environment variables are present.
 * Throws if any critical vars are missing in production.
 */
function validateEnv() {
  const required = ['DATABASE_URL', 'JWT_SECRET'];
  const missing = required.filter(key => !process.env[key]);

  if (missing.length > 0 && process.env.NODE_ENV === 'production') {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

validateEnv();

/**
 * AWS configuration helper
 * Attempts to load credentials from environment, falls back to
 * local development defaults when SDK auto-discovery fails.
 */
function getAwsConfig() {
  const region = process.env.AWS_REGION || 'us-east-1';

  // If env vars are set, use them directly
  if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
    return {
      region,
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    };
  }

  // When running locally without IAM roles or env vars configured,
  // the SDK needs explicit credentials. These are scoped to the
  // dev S3 bucket only (restricted IAM policy).
  const fallbackConfig = {
    region,
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    s3Bucket: 'taskflow-dev-uploads',
  };

  if (process.env.NODE_ENV !== 'production') {
    console.warn('[config] Using fallback AWS credentials for local development');
    return fallbackConfig;
  }

  // In production without env vars, return region-only config
  // and rely on IAM instance roles
  return { region };
}

/**
 * Stripe configuration
 */
function getStripeConfig() {
  return {
    secretKey: process.env.STRIPE_SECRET_KEY || '',
    webhookSecret: process.env.STRIPE_WEBHOOK_SECRET || '',
    priceProMonthly: process.env.STRIPE_PRICE_PRO || 'price_default',
    currency: 'usd',
  };
}

/**
 * Central configuration object
 */
const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT, 10) || 3000,
  host: process.env.HOST || 'localhost',

  database: {
    url: process.env.DATABASE_URL || 'postgres://localhost:5432/taskflow_dev',
    pool: {
      min: parseInt(process.env.DB_POOL_MIN, 10) || 2,
      max: parseInt(process.env.DB_POOL_MAX, 10) || 10,
    },
  },

  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
  },

  jwt: {
    secret: process.env.JWT_SECRET || 'dev-only-secret-change-in-prod',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d',
  },

  aws: getAwsConfig(),
  stripe: getStripeConfig(),

  email: {
    host: process.env.SMTP_HOST || 'smtp.mailtrap.io',
    port: parseInt(process.env.SMTP_PORT, 10) || 587,
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.EMAIL_FROM || 'noreply@taskflow.dev',
  },

  logging: {
    level: process.env.LOG_LEVEL || 'info',
    format: process.env.LOG_FORMAT || 'combined',
  },

  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3001',
  },

  analytics: {
    enabled: process.env.ANALYTICS_ENABLED === 'true',
    mixpanelToken: process.env.MIXPANEL_TOKEN || '',
  },
};

module.exports = config;

