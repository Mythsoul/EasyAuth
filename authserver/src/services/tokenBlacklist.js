import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger.js';

const prisma = new PrismaClient();

class TokenBlacklistService {
  
  /**
   * Add a token to the blacklist
   * @param {string} jti - JWT ID
   * @param {string} userId - User ID
   * @param {Date} expiresAt - When the token expires
   * @param {string} reason - Reason for blacklisting
   */
  static async blacklistToken(jti, userId, expiresAt, reason = 'manual_blacklist') {
    try {
      await prisma.tokenBlacklist.create({
        data: {
          jti,
          userId,
          expiresAt,
          reason
        }
      });
      
      logger.info('Token blacklisted', {
        jti: jti.substring(0, 8) + '...',
        userId,
        reason
      });
      
      return { success: true };
    } catch (error) {
      logger.error('Failed to blacklist token', {
        error: error.message,
        jti: jti.substring(0, 8) + '...',
        userId
      });
      return { success: false, error: error.message };
    }
  }

  /**
   * Blacklist all tokens for a user (e.g., after password reset)
   * @param {string} userId - User ID
   * @param {string} reason - Reason for blacklisting
   */
  static async blacklistAllUserTokens(userId, reason = 'password_reset') {
    try {
     
      const cutoffTime = new Date();
      
      await prisma.tokenBlacklist.create({
        data: {
          jti: `user_${userId}_${cutoffTime.getTime()}`, // Special format for user-wide blacklist
          userId,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours (longer than max token life)
          reason
        }
      });
      
      logger.info('All user tokens blacklisted', {
        userId,
        cutoffTime,
        reason
      });
      
      return { success: true, cutoffTime };
    } catch (error) {
      logger.error('Failed to blacklist all user tokens', {
        error: error.message,
        userId
      });
      return { success: false, error: error.message };
    }
  }

  static async isTokenBlacklisted(jti, userId, issuedAt) {
    try {
      // Check for specific JTI blacklist
      const specificBlacklist = await prisma.tokenBlacklist.findFirst({
        where: {
          jti,
          expiresAt: {
            gt: new Date() // Not expired
          }
        }
      });

      if (specificBlacklist) {
        return { isBlacklisted: true, reason: specificBlacklist.reason };
      }

      const userBlacklist = await prisma.tokenBlacklist.findFirst({
        where: {
          userId,
          jti: {
            startsWith: `user_${userId}_`
          },
          expiresAt: {
            gt: new Date()
          }
        },
        orderBy: {
          createdAt: 'desc'
        }
      });

      if (userBlacklist) {
        const cutoffTimestamp = userBlacklist.jti.split('_')[2];
        const cutoffTime = new Date(parseInt(cutoffTimestamp));
        
        if (issuedAt < cutoffTime) {
          return { isBlacklisted: true, reason: userBlacklist.reason };
        }
      }

      return { isBlacklisted: false };
    } catch (error) {
      logger.error('Error checking token blacklist', {
        error: error.message,
        jti: jti ? jti.substring(0, 8) + '...' : 'null',
        userId
      });
      return { isBlacklisted: false };
    }
  }


  static async cleanupExpiredEntries() {
    try {
      const result = await prisma.tokenBlacklist.deleteMany({
        where: {
          expiresAt: {
            lt: new Date()
          }
        }
      });
      
      if (result.count > 0) {
        logger.info('Cleaned up expired blacklist entries', {
          count: result.count
        });
      }
      
      return { success: true, cleanedCount: result.count };
    } catch (error) {
      logger.error('Failed to cleanup expired blacklist entries', {
        error: error.message
      });
      return { success: false, error: error.message };
    }
  }
}

export default TokenBlacklistService;
