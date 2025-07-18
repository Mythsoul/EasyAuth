import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { connectDatabase, prisma } from '../src/config/database.js';
import { authRoutes } from '../src/routes/auth.js';
import { logger } from '../src/utils/logger.js';
import { validateEnvConfig } from '../src/config/env.js';
import { errorHandler, notFoundHandler } from '../src/middleware/errorHandler.js';
import { globalRateLimit } from '../src/middleware/rateLimiter.js';
import { serverlessCleanup } from '../src/services/serverlessCleanup.js';

// Load environment variables
dotenv.config();

// Validate environment configuration
const config = validateEnvConfig();

const app = express();

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

// Initialize database connection
let dbConnected = false;
const initDatabase = async () => {
  if (!dbConnected) {
    try {
      await connectDatabase();
      dbConnected = true;
      logger.info('Database connected for Vercel');
    } catch (error) {
      logger.error('Database connection failed:', error);
    }
  }
};

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    await initDatabase();
    
    const health = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      platform: 'vercel'
    };

    // Check database connection
    try {
      await prisma.$queryRaw`SELECT 1`;
      health.database = 'connected';
    } catch (dbError) {
      health.database = 'disconnected';
      health.status = 'DEGRADED';
    }

    if (process.env.NODE_ENV === 'development') {
      health.environment = process.env.NODE_ENV;
      health.version = process.env.npm_package_version || '1.0.0';
      
      // Memory usage (development only)
      const memUsage = process.memoryUsage();
      health.memory = {
        rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`
      };
    }

    // Add cleanup status for serverless
    health.cleanup = serverlessCleanup.getStatus();

    const statusCode = health.status === 'OK' ? 200 : 503;
    res.status(statusCode).json(health);
  } catch (error) {
    logger.error('Health check failed', { error: error.message });
    res.status(503).json({
      status: 'ERROR',
      timestamp: new Date().toISOString(),
      platform: 'vercel'
    });
  }
});



// API routes
const apiPrefix = '/api/v1';
app.use(`${apiPrefix}/`, authRoutes);

// 404 handler
app.use('*', notFoundHandler);

// Global error handler
app.use(errorHandler);

export default async (req, res) => {
  try {
    await initDatabase();
    
    if (shouldTriggerCleanup(req)) {
      serverlessCleanup.checkAndCleanup().catch(error => {
        logger.error('Background cleanup failed:', error);
      });
    }
    
    // Handle the request
    app(req, res);
  } catch (error) {
    logger.error('Vercel handler error:', error);
    res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Serverless function error'
    });
  }
};

function shouldTriggerCleanup(req) {

  return (
    req.url === '/health' ||
    req.url.includes('/auth/login') ||
    req.url.includes('/auth/logout') ||
    req.url.includes('/auth/refresh-token') ||
    Math.random() < 0.1 
  );
}
