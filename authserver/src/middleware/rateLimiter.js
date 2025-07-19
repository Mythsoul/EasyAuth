import rateLimit from 'express-rate-limit';
import { logger } from '../utils/logger.js';

// Helper function to format milliseconds into human-readable time
const formatRetryTime = (resetTimeMs) => {
  const now = Date.now();
  const diffMs = resetTimeMs - now;
  
  if (diffMs <= 0) {
    return '0 sec';
  }
  
  const diffMinutes = Math.ceil(diffMs / (1000 * 60));
  const diffSeconds = Math.ceil(diffMs / 1000);
  
  if (diffMinutes >= 1) {
    return `${diffMinutes} min`;
  } else {
    return `${diffSeconds} sec`;
  }
};

const applicationStats = new Map();

const createKeyGenerator = (includeApplication = false) => {
  return (req) => {
    const baseKey = req.ip;
    
    if (includeApplication && req.applicationUrl) {
      // Track usage per application
      const appUrl = req.applicationUrl;
      const current = applicationStats.get(appUrl) || { requests: 0, lastReset: Date.now() };
      
      // Reset hourly stats
      if (Date.now() - current.lastReset > 60 * 60 * 1000) {
        current.requests = 0;
        current.lastReset = Date.now();
      }
      
      current.requests++;
      applicationStats.set(appUrl, current);
      
      return `${baseKey}:${appUrl}`;
    }
    
    return baseKey;
  };
};

const rateLimitHandler = (req, res) => {
  logger.warn('Rate limit exceeded', {
    ip: req.ip,
    applicationUrl: req.applicationUrl,
    path: req.path,
    method: req.method,
    userAgent: req.headers['user-agent']
  });

  res.status(429).json({
    success: false,
    error: 'RATE_LIMIT_EXCEEDED',
    message: 'Too many requests from this IP, please try again later.',
    retryAfter: formatRetryTime(req.rateLimit.resetTime)
  });
};

// Global rate limiter
export const globalRateLimit = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, 
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 50,
  keyGenerator: createKeyGenerator(false),
  handler: rateLimitHandler,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    return req.path === '/health';
  }
});

// Auth-specific rate limiter 
export const authRateLimit = rateLimit({
  windowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS) || 10,
  keyGenerator: createKeyGenerator(true),
  handler: rateLimitHandler,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    if (process.env.NODE_ENV === 'development' && 
        (req.ip === '127.0.0.1' || req.ip === '::1')) {
      return true;
    }
    return false;
  }
});

// Login-specific rate limiter
export const loginRateLimit = rateLimit({
  windowMs: parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX_REQUESTS) || 5,
  keyGenerator: createKeyGenerator(true),
  handler: (req, res) => {
    logger.warn('Login rate limit exceeded - potential brute force attack', {
      ip: req.ip,
      applicationUrl: req.applicationUrl,
      userAgent: req.headers['user-agent']
    });

    res.status(429).json({
      success: false,
      error: 'LOGIN_RATE_LIMIT_EXCEEDED',
      message: 'Too many login attempts from this IP. Please try again later.',
      retryAfter: formatRetryTime(req.rateLimit.resetTime)
    });
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    if (process.env.NODE_ENV === 'development' && 
        (req.ip === '127.0.0.1' || req.ip === '::1')) {
      return true;
    }
    return false;
  }
});

export const getApplicationStats = () => {
  const stats = {};
  
  for (const [appUrl, data] of applicationStats.entries()) {
    stats[appUrl] = {
      requests: data.requests,
      lastActivity: data.lastReset,
      requestsPerHour: data.requests 
    };
  }
  
  return stats;
};

export const cleanupApplicationStats = () => {
  const now = Date.now();
  const oneHour = 60 * 60 * 1000;
  
  for (const [appUrl, data] of applicationStats.entries()) {
    if (now - data.lastReset > oneHour) {
      applicationStats.delete(appUrl);
    }
  }
};
