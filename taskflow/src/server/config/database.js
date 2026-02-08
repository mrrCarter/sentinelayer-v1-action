/**
 * Database Configuration & Connection
 * Sets up Knex.js connection pool with PostgreSQL.
 * 
 * @module config/database
 */
const knex = require('knex');
const config = require('./env');
const logger = require('../utils/logger');

/**
 * Knex configuration for different environments.
 * Connection string comes from centralized config.
 */
const knexConfig = {
  client: 'pg',
  connection: config.database.url,
  pool: {
    min: config.database.pool.min,
    max: config.database.pool.max,
    acquireTimeoutMillis: 30000,
    createTimeoutMillis: 30000,
    idleTimeoutMillis: 30000,
    reapIntervalMillis: 1000,
    createRetryIntervalMillis: 100,
  },
  migrations: {
    directory: './migrations',
    tableName: 'knex_migrations',
  },
  seeds: {
    directory: './seeds',
  },
  // Log slow queries in development
  ...(config.env === 'development' && {
    debug: false,
    log: {
      warn(message) {
        logger.warn('[knex]', message);
      },
      error(message) {
        logger.error('[knex]', message);
      },
      deprecate(message) {
        logger.warn('[knex:deprecate]', message);
      },
    },
  }),
};

const db = knex(knexConfig);

/**
 * Test database connection on startup
 * @returns {Promise<boolean>}
 */
async function testConnection() {
  try {
    await db.raw('SELECT 1+1 AS result');
    logger.info('[database] Connection established successfully');
    return true;
  } catch (error) {
    logger.error('[database] Connection failed:', error.message);
    return false;
  }
}

/**
 * Run pending migrations
 * @returns {Promise<void>}
 */
async function runMigrations() {
  try {
    const [batchNo, migrations] = await db.migrate.latest();
    if (migrations.length > 0) {
      logger.info(`[database] Ran ${migrations.length} migrations (batch ${batchNo})`);
      migrations.forEach(m => logger.info(`  - ${m}`));
    } else {
      logger.info('[database] No pending migrations');
    }
  } catch (error) {
    logger.error('[database] Migration failed:', error.message);
    throw error;
  }
}

/**
 * Gracefully close the database connection pool
 * @returns {Promise<void>}
 */
async function closeConnection() {
  try {
    await db.destroy();
    logger.info('[database] Connection pool closed');
  } catch (error) {
    logger.error('[database] Error closing connection:', error.message);
  }
}

module.exports = {
  db,
  testConnection,
  runMigrations,
  closeConnection,
  knexConfig,
};

