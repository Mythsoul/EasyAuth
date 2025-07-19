import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger.js';

// Create Prisma client with better configuration
export const prisma = new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['query', 'info', 'warn', 'error'] : ['error'],
  datasources: {
    db: {
      url: process.env.DATABASE_URL
    }
  },
  // Connection pool configuration
  __internal: {
    engine: {
      connectTimeout: 60000, // 60 seconds
      poolTimeout: 60000,    // 60 seconds
    }
  }
});

let isConnected = false;
let isConnecting = false;

export async function connectDatabase() {
  if (isConnected) {
    logger.info('Database already connected');
    return;
  }
  
  if (isConnecting) {
    logger.info('Database connection already in progress');
    return;
  }
  
  try {
    isConnecting = true;
    logger.info('Attempting to connect to database...');
    
    // Test the connection
    await prisma.$connect();
    await prisma.$queryRaw`SELECT 1`;
    
    isConnected = true;
    isConnecting = false;
    logger.info('Database connected successfully');
    
    // Setup connection monitoring
    setupConnectionMonitoring();
    
  } catch (error) {
    isConnecting = false;
    logger.error('Database connection failed:', {
      error: error.message,
      stack: error.stack,
      databaseUrl: process.env.DATABASE_URL ? 'configured' : 'missing'
    });
    throw error;
  }
}

// Monitor database connection health
function setupConnectionMonitoring() {
  // Check connection every 30 seconds
  const healthCheckInterval = globalThis.setInterval(async () => {
    try {
      await prisma.$queryRaw`SELECT 1`;
    } catch (error) {
      logger.error('Database health check failed:', error.message);
      isConnected = false;
      
      // Try to reconnect
      try {
        await prisma.$connect();
        isConnected = true;
        logger.info('Database reconnected successfully');
      } catch (reconnectError) {
        logger.error('Database reconnection failed:', reconnectError.message);
      }
    }
  }, 30000);
  
  // Store interval reference for cleanup
  process.healthCheckInterval = healthCheckInterval;
}

// Graceful shutdown with proper cleanup
async function gracefulShutdown(signal) {
  logger.info(`Received ${signal}, starting graceful database shutdown...`);
  
  try {
    // Clear health check interval
    if (process.healthCheckInterval) {
      globalThis.clearInterval(process.healthCheckInterval);
    }
    
    // Close database connection
    if (isConnected) {
      await prisma.$disconnect();
      isConnected = false;
      logger.info('Database disconnected successfully');
    }
    
    // Give time for cleanup
    globalThis.setTimeout(() => {
      logger.info('Graceful shutdown complete');
      process.exit(0);
    }, 1000);
    
  } catch (error) {
    logger.error('Error during database shutdown:', error.message);
    process.exit(1);
  }
}

// Setup graceful shutdown handlers
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGUSR2', () => gracefulShutdown('SIGUSR2')); // Nodemon restart

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't exit immediately, just log the error
});

// Export connection status checker
export function getDatabaseStatus() {
  return {
    isConnected,
    isConnecting
  };
}

