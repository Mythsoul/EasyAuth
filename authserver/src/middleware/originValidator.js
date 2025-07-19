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
      const originUrl = new globalThis.URL(origin);
      
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
    const { applicationUrl, originInfo } = req;
    
    if (!applicationUrl || !originInfo) {
      logger.warn('Missing origin data in strict validation', {
        applicationUrl,
        hasOriginInfo: !!originInfo,
        ip: req.ip,
        path: req.path
      });
      
      return res.status(400).json({
        success: false,
        error: 'MISSING_ORIGIN_DATA',
        message: 'Origin validation data is missing'
      });
    }

    const urlObj = new globalThis.URL(applicationUrl);
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
      /data:/i,
      /javascript:/i,
      /vbscript:/i,
      /file:/i,
      /ftp:/i
    ];
    
    if (suspiciousPatterns.some(pattern => pattern.test(applicationUrl))) {
      logger.warn('Suspicious origin protocol detected', {
        applicationUrl,
        ip: req.ip,
        path: req.path
      });
      
      return res.status(403).json({
        success: false,
        error: 'SUSPICIOUS_ORIGIN',
        message: 'Origin protocol not allowed'
      });
    }
    
    // Validate protocol (only HTTP/HTTPS)
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      logger.warn('Invalid protocol in origin', {
        protocol: urlObj.protocol,
        applicationUrl,
        ip: req.ip
      });
      
      return res.status(403).json({
        success: false,
        error: 'INVALID_PROTOCOL',
        message: 'Only HTTP and HTTPS protocols are allowed'
      });
    }
    
    // In production, enforce HTTPS
    if (process.env.NODE_ENV === 'production' && urlObj.protocol !== 'https:') {
      logger.warn('Non-HTTPS origin in production', {
        applicationUrl,
        ip: req.ip
      });
      
      return res.status(403).json({
        success: false,
        error: 'HTTPS_REQUIRED',
        message: 'HTTPS is required in production'
      });
    }
    
    if (process.env.NODE_ENV === 'production') {
      const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
      if (ipPattern.test(urlObj.hostname)) {
        logger.warn('IP address origin in production', {
          hostname: urlObj.hostname,
          applicationUrl,
          ip: req.ip
        });
        
        return res.status(403).json({
          success: false,
          error: 'IP_ORIGIN_NOT_ALLOWED',
          message: 'IP address origins are not allowed in production'
        });
      }
    }

    next();
  } catch (error) {
    logger.error('Strict origin validation error', {
      error: error.message,
      stack: error.stack,
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
    const urlObj = new globalThis.URL(url);
    // Remove trailing slash and convert to lowercase
    return `${urlObj.protocol}//${urlObj.hostname.toLowerCase()}${urlObj.port ? `:${urlObj.port}` : ''}`;
  } catch {
    return url;
  }
};
