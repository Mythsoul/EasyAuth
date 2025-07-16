import jwt from 'jsonwebtoken';
import { logger } from '../utils/logger.js';
import { parseCookie } from '../utils/cookieUtils.js';

const extractToken = (req) => {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  
  if (authHeader) {
    const parts = authHeader.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      return parts[1];
    }
  }
  
  return parseCookie(req, 'token');
};

export const authenticateToken = (req, res, next) => {
  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'ACCESS_TOKEN_REQUIRED',
      message: 'Access token is required'
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    logger.warn('Invalid token attempt', {
      error: error.message,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'TOKEN_EXPIRED',
        message: 'Token has expired'
      });
    }

    return res.status(403).json({
      success: false,
      error: 'INVALID_TOKEN',
      message: 'Invalid token'
    });
  }
};

export const optionalAuth = (req, res, next) => {
  const token = extractToken(req);

  if (!token) {
    req.user = null;
    return next();
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
  } catch (error) {
    req.user = null;
  }

  next();
};
