import { PrismaClient } from '@prisma/client';
import { logger } from './logger.js';

const prisma = new PrismaClient();

export const cleanupExpiredTokens = async () => {
  try {
    const now = new Date();
    
    // Clean up expired refresh tokens
    const expiredRefreshTokens = await prisma.refreshToken.deleteMany({
      where: {
        expiresAt: {
          lt: now
        }
      }
    });
    
    // Clean up expired sessions
    const expiredSessions = await prisma.session.deleteMany({
      where: {
        expiresAt: {
          lt: now
        }
      }
    });
    
    // Clean up expired email verification tokens
    const expiredEmailTokens = await prisma.user.updateMany({
      where: {
        emailVerifyTokenExpiresAt: {
          lt: now
        }
      },
      data: {
        emailVerifyToken: null,
        emailVerifyTokenExpiresAt: null
      }
    });
    
    // Clean up expired password reset tokens
    const expiredPasswordTokens = await prisma.user.updateMany({
      where: {
        passwordResetExpiresAt: {
          lt: now
        }
      },
      data: {
        passwordResetToken: null,
        passwordResetExpiresAt: null
      }
    });
    
    logger.info('Database cleanup completed', {
      expiredRefreshTokens: expiredRefreshTokens.count,
      expiredSessions: expiredSessions.count,
      expiredEmailTokens: expiredEmailTokens.count,
      expiredPasswordTokens: expiredPasswordTokens.count,
      timestamp: now.toISOString()
    });
    
    return {
      success: true,
      cleaned: {
        refreshTokens: expiredRefreshTokens.count,
        sessions: expiredSessions.count,
        emailTokens: expiredEmailTokens.count,
        passwordTokens: expiredPasswordTokens.count
      }
    };
    
  } catch (error) {
    logger.error('Database cleanup error', {
      error: error.message,
      stack: error.stack
    });
    
    return {
      success: false,
      error: error.message
    };
  }
};

export const cleanupInactiveUsers = async (daysInactive = 90) => {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysInactive);
    
    // Find users who haven't logged in for X days and are not email verified
    const inactiveUsers = await prisma.user.findMany({
      where: {
        OR: [
          {
            lastLogin: {
              lt: cutoffDate
            },
            emailVerified: false
          },
          {
            lastLogin: null,
            createdAt: {
              lt: cutoffDate
            },
            emailVerified: false
          }
        ]
      },
      select: {
        id: true,
        email: true,
        applicationUrl: true,
        lastLogin: true,
        createdAt: true
      }
    });
    
    let deletedCount = 0;
    
    for (const user of inactiveUsers) {
      // Delete user and all related data (CASCADE will handle relationships)
      await prisma.user.delete({
        where: { id: user.id }
      });
      deletedCount++;
    }
    
    logger.info('Inactive users cleanup completed', {
      deletedUsers: deletedCount,
      cutoffDate: cutoffDate.toISOString(),
      daysInactive
    });
    
    return {
      success: true,
      deletedUsers: deletedCount,
      cutoffDate
    };
    
  } catch (error) {
    logger.error('Inactive users cleanup error', {
      error: error.message,
      stack: error.stack
    });
    
    return {
      success: false,
      error: error.message
    };
  }
};

// Run cleanup if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const runCleanup = async () => {
    try {
      logger.info('Starting database cleanup...');
      
      // Only run safe cleanup automatically
      await cleanupExpiredTokens();
      
      // DO NOT run user cleanup automatically - too dangerous!
      logger.info('User cleanup skipped for safety - run manually if needed');
      
      logger.info('Database cleanup completed successfully');
      process.exit(0);
    } catch (error) {
      logger.error('Database cleanup failed', error);
      process.exit(1);
    } finally {
      await prisma.$disconnect();
    }
  };
  
  runCleanup();
}
