import { cleanupExpiredTokens, cleanupInactiveUsers } from '../utils/cleanup.js';
import { cleanupApplicationStats } from '../middleware/rateLimiter.js';
import { logger } from '../utils/logger.js';

class CleanupScheduler {
  constructor() {
    this.intervals = new Map();
    this.isRunning = false;
  }

  start() {
    if (this.isRunning) {
      logger.warn('Cleanup scheduler is already running');
      return;
    }

    if (process.env.CLEANUP_ENABLED === 'false') {
      logger.info('Cleanup scheduler is disabled via environment variable');
      return;
    }

    this.isRunning = true;
    logger.info('Starting cleanup scheduler');

    const expiredTokensInterval = parseInt(process.env.CLEANUP_EXPIRED_TOKENS_INTERVAL_MINUTES) || 60;

    // Schedule different cleanup tasks at different intervals
    this.scheduleCleanup('expiredTokens', this.runExpiredTokensCleanup, {
      intervalMinutes: expiredTokensInterval,
      runOnStart: true     // Run immediately on startup
    });

    this.scheduleCleanup('applicationStats', this.runApplicationStatsCleanup, {
      intervalMinutes: 60, // Run every hour
      runOnStart: false
    });


    logger.info('Cleanup scheduler started successfully');
  }

  stop() {
    if (!this.isRunning) {
      logger.warn('Cleanup scheduler is not running');
      return;
    }

    logger.info('Stopping cleanup scheduler');
    
    // Clear all intervals
    for (const [taskName, intervalId] of this.intervals) {
      clearInterval(intervalId);
      logger.info(`Stopped cleanup task: ${taskName}`);
    }

    this.intervals.clear();
    this.isRunning = false;
    logger.info('Cleanup scheduler stopped');
  }

  scheduleCleanup(taskName, cleanupFunction, options = {}) {
    const { intervalMinutes = 60, runOnStart = false } = options;
    const intervalMs = intervalMinutes * 60 * 1000;

    // Run immediately if requested
    if (runOnStart) {
      this.safeExecute(taskName, cleanupFunction.bind(this));
    }

    // Schedule recurring execution
    const intervalId = setInterval(() => {
      this.safeExecute(taskName, cleanupFunction.bind(this));
    }, intervalMs);

    this.intervals.set(taskName, intervalId);
    
    logger.info(`Scheduled cleanup task: ${taskName}`, {
      intervalMinutes,
      runOnStart,
      nextRun: new Date(Date.now() + intervalMs).toISOString()
    });
  }

  async safeExecute(taskName, cleanupFunction) {
    try {
      logger.info(`Starting scheduled cleanup: ${taskName}`);
      const startTime = Date.now();
      
      const result = await cleanupFunction();
      
      const duration = Date.now() - startTime;
      logger.info(`Completed scheduled cleanup: ${taskName}`, {
        duration: `${duration}ms`,
        result: result
      });
      
    } catch (error) {
      logger.error(`Error in scheduled cleanup: ${taskName}`, {
        error: error.message,
        stack: error.stack
      });
    }
  }

  async runExpiredTokensCleanup() {
    return await cleanupExpiredTokens();
  }


  async runApplicationStatsCleanup() {
    cleanupApplicationStats();
    return { message: 'Application stats cleaned' };
  }

  // Get status of scheduler
  getStatus() {
    return {
      isRunning: this.isRunning,
      scheduledTasks: Array.from(this.intervals.keys()),
      taskCount: this.intervals.size
    };
  }
}

// Export singleton instance
export const cleanupScheduler = new CleanupScheduler();

// Graceful shutdown handling
process.on('SIGTERM', () => {
  logger.info('Received SIGTERM, stopping cleanup scheduler');
  cleanupScheduler.stop();
});

process.on('SIGINT', () => {
  logger.info('Received SIGINT, stopping cleanup scheduler');
  cleanupScheduler.stop();
});
