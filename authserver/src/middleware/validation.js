import Joi from 'joi';
import { logger } from '../utils/logger.js';
import { domainValidator } from '../helpers/domainValidator.js';

const validateEmailWithDomain = async (value, helpers) => {
  try {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(value)) {
      return helpers.error('string.email');
    }

    if (process.env.ENABLE_DOMAIN_VALIDATION === 'true') {
      const domainResult = await domainValidator.validateEmailDomain(value);
      
      if (!domainResult.valid) {
        switch (domainResult.reason) {
          case 'DISPOSABLE_EMAIL':
            return helpers.error('email.disposable');
          case 'DOMAIN_NOT_FOUND':
            return helpers.error('email.domain.notfound');
          case 'INVALID_EMAIL_FORMAT':
            return helpers.error('string.email');
          default:
            return helpers.error('email.domain.invalid');
        }
      }
    }

    return value;
  } catch (error) {
    logger.error('Email validation error', {
      email: value,
      error: error.message
    });
    return value;
  }
};

const customEmailSchema = Joi.string().external(validateEmailWithDomain).messages({
  'string.email': 'Please provide a valid email address',
  'email.disposable': 'Disposable email addresses are not allowed',
  'email.domain.notfound': 'Email domain does not exist',
  'email.domain.invalid': 'Email domain is not valid'
});

export const validate = (schema) => {
  return async (req, res, next) => {
    try {
      const value = await schema.validateAsync(req.body, {
        abortEarly: false,
        stripUnknown: true
      });
      req.body = value;
      next();
    } catch (error) {
      let errorDetails;
      
      // Handle external validation errors differently
      if (error.name === 'ValidationError' && error.details) {
        errorDetails = error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message
        }));
      } else if (error.message && error.message.includes('external')) {
        // Handle external validation errors with custom messages
        const errorType = error.message.match(/"(.*?)"/)?.[1] || 'validation';
        const customMessages = {
          'email.disposable': 'Disposable email addresses are not allowed',
          'email.domain.notfound': 'Email domain does not exist', 
          'email.domain.invalid': 'Email domain is not valid',
          'string.email': 'Please provide a valid email address'
        };
        
        errorDetails = [{
          field: 'email',
          message: customMessages[errorType] || 'Email validation failed'
        }];
      } else {
        // Fallback for other errors
        errorDetails = [{
          field: 'unknown',
          message: error.message || 'Validation failed'
        }];
      }

      logger.warn('Validation error', {
        path: req.path,
        method: req.method,
        ip: req.ip,
        errors: errorDetails,
        applicationUrl: req.applicationUrl
      });

      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Invalid input data',
        details: errorDetails
      });
    }
  };
};

export const validateQuery = (schema) => {
  return async (req, res, next) => {
    try {
      const value = await schema.validateAsync(req.query, {
        abortEarly: false,
        stripUnknown: true
      });
      req.query = value;
      next();
    } catch (error) {
      let errorDetails;
      
      // Handle external validation errors differently
      if (error.name === 'ValidationError' && error.details) {
        errorDetails = error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message
        }));
      } else if (error.message && error.message.includes('external')) {
        // Handle external validation errors with custom messages
        const errorType = error.message.match(/"(.*?)"/)?.[1] || 'validation';
        const customMessages = {
          'email.disposable': 'Disposable email addresses are not allowed',
          'email.domain.notfound': 'Email domain does not exist', 
          'email.domain.invalid': 'Email domain is not valid',
          'string.email': 'Please provide a valid email address'
        };
        
        errorDetails = [{
          field: 'email',
          message: customMessages[errorType] || 'Email validation failed'
        }];
      } else {
        // Fallback for other errors
        errorDetails = [{
          field: 'unknown',
          message: error.message || 'Validation failed'
        }];
      }

      logger.warn('Validation error', {
        path: req.path,
        method: req.method,
        ip: req.ip,
        errors: errorDetails,
        applicationUrl: req.applicationUrl
      });

      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Invalid input data',
        details: errorDetails
      });
    }
  };
};

// Validation schemas
export const authSchemas = {
  register: Joi.object({
    email: customEmailSchema.required().messages({
      'any.required': 'Email is required',
      'string.email': 'Please provide a valid email address',
      'email.disposable': 'Disposable email addresses are not allowed',
      'email.domain.notfound': 'Email domain does not exist',
      'email.domain.invalid': 'Email domain is not valid'
    }),
    password: Joi.string().min(8).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$')).required().messages({
      'string.min': 'Password must be at least 8 characters long',
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      'any.required': 'Password is required'
    }),
    username: Joi.string().min(3).max(30).alphanum().optional().messages({
      'string.min': 'Username must be at least 3 characters long',
      'string.max': 'Username must not exceed 30 characters',
    'string.alphanum': 'Username can only contain letters and numbers'
    }),
    emailConfig: Joi.object({
      sendVerificationEmail: Joi.boolean().optional(),
    }).optional()
  }),

  oauthRedirect: Joi.object({
    redirectUrl: Joi.string().uri().required().messages({
      'any.required': 'Redirect URL is required',
      'string.uri': 'Redirect URL must be a valid URI'
    })
  }),
  login: Joi.object({
    email: customEmailSchema.required().messages({
      'any.required': 'Email is required'
    }),
    password: Joi.string().required().messages({
      'any.required': 'Password is required'
    })
  }),

  refreshToken: Joi.object({
    refreshToken: Joi.string().required().messages({
      'any.required': 'Refresh token is required'
    })
  }),

  verifyEmail: Joi.object({
    token: Joi.string().required().messages({
      'any.required': 'Verification token is required'
    })
  }),

  forgotPassword: Joi.object({
    email: customEmailSchema.required().messages({
      'any.required': 'Email is required'
    })
  }),

  resetPassword: Joi.object({
    token: Joi.string().required().messages({
      'any.required': 'Reset token is required'
    }),
    password: Joi.string().min(8).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$')).required().messages({
      'string.min': 'Password must be at least 8 characters long',
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      'any.required': 'Password is required'
    })
  }),

  resendVerification: Joi.object({
    email: customEmailSchema.required().messages({
      'any.required': 'Email is required'
    })
  })
};
