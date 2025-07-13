import { logger } from '../utils/logger.js';

export const originValidator = (req, res, next) => {
  try {
    const origin = req.headers.origin || 
                  req.headers.referer?.split('/').slice(0, 3).join('/') ||
                  req.get('host') && `${req.protocol}://${req.get('host')}`;

    if (!origin) {
      logger.warn('No origin detected in request', {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        path: req.path
      });
      
      return res.status(400).json({
        success: false,
        error: 'ORIGIN_REQUIRED',
        message: 'Request origin could not be determined. Please ensure your application is properly configured.'
      });
    }

    try {
      const originUrl = new URL(origin);
      
      if (process.env.NODE_ENV === 'production') {
        const isLocalhost = originUrl.hostname === 'localhost' || 
                           originUrl.hostname === '127.0.0.1' ||
                           originUrl.hostname.endsWith('.localhost');
        
        if (isLocalhost) {
          return res.status(403).json({
            success: false,
            error: 'LOCALHOST_NOT_ALLOWED',
            message: 'Localhost origins are not allowed in production'
          });
        }
      }

      req.applicationUrl = origin;
      req.originInfo = {
        hostname: originUrl.hostname,
        protocol: originUrl.protocol,
        port: originUrl.port,
        fullOrigin: origin
      };

      logger.info('Origin validated successfully', {
        origin,
        ip: req.ip,
        path: req.path
      });

      next();
    } catch (urlError) {
      logger.warn('Invalid origin URL format', {
        origin,
        error: urlError.message,
        ip: req.ip
      });
      
      return res.status(400).json({
        success: false,
        error: 'INVALID_ORIGIN',
        message: 'Invalid origin URL format'
      });
    }
  } catch (error) {
    logger.error('Origin validation error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });
    
    return res.status(500).json({
      success: false,
      error: 'ORIGIN_VALIDATION_ERROR',
      message: 'Internal server error during origin validation'
    });
  }
};

export const strictOriginValidator = async (req, res, next) => {
  try {
    const { applicationUrl } = req;
    

    logger.info('Strict origin validation', {
      applicationUrl,
      ip: req.ip,
      path: req.path
    });
    
    next();
  } catch (error) {
    logger.error('Strict origin validation error', {
      error: error.message,
      ip: req.ip
    });
    
    return res.status(500).json({
      success: false,
      error: 'STRICT_ORIGIN_VALIDATION_ERROR',
      message: 'Internal server error during strict origin validation'
    });
  }
};

/**
 */
export const normalizeUrl = (url) => {
  try {
    const urlObj = new URL(url);
    // Remove trailing slash and convert to lowercase
    return `${urlObj.protocol}//${urlObj.hostname.toLowerCase()}${urlObj.port ? `:${urlObj.port}` : ''}`;
  } catch (error) {
    return url;
  }
};
