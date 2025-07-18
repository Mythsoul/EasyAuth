import { logger } from '../utils/logger.js';

export const errorHandler = (err, req, res, next) => {
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    applicationUrl: req.applicationUrl
  });

  if (process.env.NODE_ENV === 'production') {
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected error occurred'
    });
  }

  return res.status(500).json({
    success: false,
    error: 'INTERNAL_SERVER_ERROR',
    message: err.message,
    stack: err.stack
  });
};

export const notFoundHandler = (req, res) => {
  logger.warn('Route not found', {
    path: req.path,
    method: req.method,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    applicationUrl: req.applicationUrl
  });

  res.status(404).json({
    success: false,
    error: 'ROUTE_NOT_FOUND',
    message: `The route ${req.method} ${req.path} does not exist`
  });
};
