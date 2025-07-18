import { logger } from '../utils/logger.js';

// Define required environment variables
const requiredEnvVars = [
  'DATABASE_URL',
  'JWT_SECRET',
  'JWT_REFRESH_SECRET'
];

const optionalEnvVars = {
  PORT: '3000',
  NODE_ENV: 'development' ,
  JWT_EXPIRES_IN: '15m',
  JWT_REFRESH_EXPIRES_IN: '7d',
  SALT_ROUNDS: '12',
  RATE_LIMIT_WINDOW_MS: '900000', // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: '100',
  AUTH_RATE_LIMIT_WINDOW_MS: '900000', // 15 minutes
  AUTH_RATE_LIMIT_MAX_REQUESTS: '20',
  LOGIN_RATE_LIMIT_WINDOW_MS: '900000', // 15 minutes
  LOGIN_RATE_LIMIT_MAX_REQUESTS: '5'
};

// Validate and set defaults for environment variables
export const validateEnvConfig = () => {
  const missingVars = [];
  const warnings = [];

  // Check required variables
  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      missingVars.push(envVar);
    }
  }

  // Set defaults for optional variables
  for (const [envVar, defaultValue] of Object.entries(optionalEnvVars)) {
    if (!process.env[envVar]) {
      process.env[envVar] = defaultValue;
      warnings.push(`${envVar} not set, using default: ${defaultValue}`);
    }
  }

  // Log warnings about defaults
  if (warnings.length > 0) {
    logger.warn('Using default values for environment variables', {
      warnings: warnings
    });
  }

  // Validate specific environment variables
  const validationErrors = [];

  // Validate JWT secrets
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    validationErrors.push('JWT_SECRET should be at least 32 characters long for security');
  }

  if (process.env.JWT_REFRESH_SECRET && process.env.JWT_REFRESH_SECRET.length < 32) {
    validationErrors.push('JWT_REFRESH_SECRET should be at least 32 characters long for security');
  }

  // Validate SALT_ROUNDS
  const saltRounds = parseInt(process.env.SALT_ROUNDS);
  if (isNaN(saltRounds) || saltRounds < 10 || saltRounds > 15) {
    validationErrors.push('SALT_ROUNDS should be a number between 10 and 15');
  }

  // Validate rate limit values
  const rateLimitWindow = parseInt(process.env.RATE_LIMIT_WINDOW_MS);
  if (isNaN(rateLimitWindow) || rateLimitWindow < 60000) {
    validationErrors.push('RATE_LIMIT_WINDOW_MS should be at least 60000 (1 minute)');
  }

  const rateLimitMax = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS);
  if (isNaN(rateLimitMax) || rateLimitMax < 1) {
    validationErrors.push('RATE_LIMIT_MAX_REQUESTS should be at least 1');
  }

  // Validate production-specific requirements
  if (process.env.NODE_ENV === 'production') {
    if (process.env.JWT_SECRET === 'your-super-secret-jwt-key-here') {
      validationErrors.push('JWT_SECRET must be changed from default value in production');
    }
    
    if (process.env.JWT_REFRESH_SECRET === 'your-refresh-token-secret-here') {
      validationErrors.push('JWT_REFRESH_SECRET must be changed from default value in production');
    }

    if (!process.env.SERVER_URL || process.env.SERVER_URL.includes('localhost')) {
      validationErrors.push('SERVER_URL must be set to production URL in production environment');
    }
  }

  // Report errors
  if (missingVars.length > 0) {
    logger.error('Missing required environment variables', {
      missingVars: missingVars
    });
    throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
  }

  if (validationErrors.length > 0) {
    logger.error('Environment variable validation errors', {
      errors: validationErrors
    });
    throw new Error(`Environment validation errors: ${validationErrors.join(', ')}`);
  }

  // Log successful validation
  logger.info('Environment variables validated successfully', {
    nodeEnv: process.env.NODE_ENV,
    port: process.env.PORT,
    jwtExpiresIn: process.env.JWT_EXPIRES_IN,
    saltRounds: process.env.SALT_ROUNDS
  });

  return {
    port: parseInt(process.env.PORT),
    nodeEnv: process.env.NODE_ENV,
    databaseUrl: process.env.DATABASE_URL,
    jwtSecret: process.env.JWT_SECRET,
    jwtRefreshSecret: process.env.JWT_REFRESH_SECRET,
    jwtExpiresIn: process.env.JWT_EXPIRES_IN,
    jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
    saltRounds: parseInt(process.env.SALT_ROUNDS),
    rateLimits: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS),
      maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS),
      authWindowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS),
      authMaxRequests: parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS),
      loginWindowMs: parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS),
      loginMaxRequests: parseInt(process.env.LOGIN_RATE_LIMIT_MAX_REQUESTS)
    }
  };
};
