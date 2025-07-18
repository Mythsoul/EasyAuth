import { cleanupExpiredTokens } from '../utils/cleanup.js';
import { logger } from '../utils/logger.js';

class ServerlessCleanup {
  constructor() {
    this.lastCleanup = null;
    this.cleanupInterval = 60 * 60 * 1000; // 1 hour in milliseconds
  }


  async checkAndCleanup() {
    try {
      const now = Date.now();
      
  
      if (this.shouldRunCleanup(now)) {
        logger.info('Running on-demand cleanup in serverless environment');
        
        const result = await cleanupExpiredTokens();
        
        this.lastCleanup = now;
        
        logger.info('Serverless cleanup completed', {
          result: result,
          timestamp: new Date().toISOString()
        });
        
        return result;
      }
      
      return { skipped: true, reason: 'Not needed yet' };
    } catch (error) {
      logger.error('Serverless cleanup failed', {
        error: error.message,
        stack: error.stack
      });
      
      return { success: false, error: error.message };
    }
  }

  
  shouldRunCleanup(now) {
    // Run cleanup if:
    // 1. Never run before, OR
    // 2. More than 1 hour since last cleanup
    return !this.lastCleanup || (now - this.lastCleanup > this.cleanupInterval);
  }

  async forceCleanup() {
    try {
      logger.info('Forcing cleanup in serverless environment');
      
      const result = await cleanupExpiredTokens();
      
      this.lastCleanup = Date.now();
      
      logger.info('Forced serverless cleanup completed', {
        result: result,
        timestamp: new Date().toISOString()
      });
      
      return result;
    } catch (error) {
      logger.error('Forced serverless cleanup failed', {
        error: error.message,
        stack: error.stack
      });
      
      return { success: false, error: error.message };
    }
  }

  getStatus() {
    return {
      lastCleanup: this.lastCleanup ? new Date(this.lastCleanup).toISOString() : 'never',
      nextCleanup: this.lastCleanup ? 
        new Date(this.lastCleanup + this.cleanupInterval).toISOString() : 'on next trigger',
      cleanupInterval: `${this.cleanupInterval / 1000 / 60} minutes`,
      environment: 'serverless'
    };
  }
}
export const serverlessCleanup = new ServerlessCleanup();
