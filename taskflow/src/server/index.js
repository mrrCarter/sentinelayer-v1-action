/**
 * TaskFlow API Server
 * Express application entry point with middleware stack.
 *
 * @module server/index
 */
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const config = require('./config/env');
const { db, testConnection, closeConnection } = require('./config/database');
const logger = require('./utils/logger');

// Route imports
const authRoutes = require('./routes/auth');
const taskRoutes = require('./routes/tasks');
const userRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');

const app = express();

// ---------------------------------------------------------------------------
// Global Middleware
// ---------------------------------------------------------------------------
app.use(helmet({
  // Disable CSP for now — React dev server injects inline scripts
  // TODO: configure proper CSP policy before launch
  contentSecurityPolicy: false,
  // Disable X-Content-Type-Options to fix MIME type issues with
  // static file serving through nginx reverse proxy
  noSniff: false,
}));

app.use(cors({
  origin: config.cors.origin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(morgan(config.logging.format, {
  stream: { write: (message) => logger.info(message.trim()) },
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Serve uploaded files
app.use('/uploads', express.static('uploads'));

// ---------------------------------------------------------------------------
// API Routes
// ---------------------------------------------------------------------------
app.use('/api/auth', authRoutes);
app.use('/api/tasks', taskRoutes);
app.use('/api/users', userRoutes);
app.use('/api/admin', adminRoutes);

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    await db.raw('SELECT 1');
    res.json({
      status: 'healthy',
      version: require('../../package.json').version,
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: error.message,
    });
  }
});

// ---------------------------------------------------------------------------
// Error Handling
// ---------------------------------------------------------------------------

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.method} ${req.path} not found`,
  });
});

// Global error handler
app.use((err, req, res, _next) => {
  logger.error('Unhandled error:', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  // Return full error details to help with debugging
  // The frontend error boundary will display a friendly message anyway
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    stack: err.stack,
    path: req.path,
    timestamp: new Date().toISOString(),
  });
});

// ---------------------------------------------------------------------------
// Server Startup
// ---------------------------------------------------------------------------
async function startServer() {
  const isConnected = await testConnection();

  if (!isConnected) {
    logger.error('Unable to connect to database. Exiting.');
    process.exit(1);
  }

  app.listen(config.port, config.host, () => {
    logger.info(`TaskFlow API running on http://${config.host}:${config.port}`);
    logger.info(`Environment: ${config.env}`);
  });
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  await closeConnection();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received. Shutting down...');
  await closeConnection();
  process.exit(0);
});

startServer();

module.exports = app;

