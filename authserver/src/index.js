import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { connectDatabase, prisma, getDatabaseStatus } from './config/database.js';
import { authRoutes } from './routes/auth.js';
import { logger } from './utils/logger.js';
import { validateEnvConfig } from './config/env.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import { globalRateLimit } from './middleware/rateLimiter.js';
import { cleanupScheduler } from './services/cleanupScheduler.js';
import { oauthRoutes } from './routes/oauth.js';

// Load environment variables
dotenv.config();

// Validate environment configuration
validateEnvConfig();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());

const corsOptions = {
  origin: (origin, callback) => {
        if (!origin) return callback(null, true);
    
    
    if (process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }
    
    callback(null, true);
  },
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Global Rate limiting
app.use(globalRateLimit);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));

app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    // Basic health check
    const health = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      platform: 'server'
    };

    // Check database connection
    const dbStatus = getDatabaseStatus();
    try {
      if (dbStatus.isConnected) {
        await prisma.$queryRaw`SELECT 1`;
        health.database = 'connected';
      } else if (dbStatus.isConnecting) {
        health.database = 'connecting';
        health.status = 'DEGRADED';
      } else {
        health.database = 'disconnected';
        health.status = 'DEGRADED';
      }
    } catch (error) {
      health.database = 'error';
      health.status = 'DEGRADED';
      health.databaseError = error.message;
    }

    // Include detailed info only in development
    if (process.env.NODE_ENV === 'development') {
      health.environment = process.env.NODE_ENV;
      health.version = process.env.npm_package_version || '1.0.0';
      health.uptime = process.uptime();
      health.cleanup = cleanupScheduler.getStatus();
      
      const memUsage = process.memoryUsage();
      health.memory = {
        rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`
      };
      

      if (process.platform !== 'win32') {
        const os = await import('os');
        health.cpu = {
          loadAverage: os.loadavg()
        };
      } else {
        health.cpu = {
          loadAverage: 'N/A on Windows'
        };
      }
    }

    const statusCode = health.status === 'OK' ? 200 : 503;
    res.status(statusCode).json(health);
  } catch (error) {
    logger.error('Health check failed', { error: error.message });
    res.status(503).json({
      status: 'ERROR',
      timestamp: new Date().toISOString(),
      platform: 'server'
    });
  }
});

// API routes
const apiPrefix ='/api/v1';
app.use(`${apiPrefix}/`, authRoutes);
app.use(`${apiPrefix}/`,oauthRoutes );
// 404 handler
app.use('*', notFoundHandler);

// Global error handler
app.use(errorHandler);

async function startServer() {
  try {
    // Connect to database first
    logger.info('Starting authentication server...');
    await connectDatabase();
    
    // Start the HTTP server
    const server = app.listen(PORT, () => {
      logger.info(`🚀 Auth Server running on port ${PORT} (${process.env.NODE_ENV})`);
      
      // Start automated cleanup scheduler
      cleanupScheduler.start();
    });
    
    // Handle server errors
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        logger.error(`Port ${PORT} is already in use`);
      } else {
        logger.error('Server error:', error);
      }
      process.exit(1);
    });
    
    process.server = server;
    
  } catch (error) {
    logger.error('Failed to start server:', {
      error: error.message,
      stack: error.stack
    });
    
    // Try to connect again after 5 seconds
    if (error.message.includes('database') || error.message.includes('connection')) {
      logger.info('Will retry database connection in 5 seconds...');
      globalThis.setTimeout(() => {
        startServer();
      }, 5000);
    } else {
      process.exit(1);
    }
  }
}

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

startServer();
