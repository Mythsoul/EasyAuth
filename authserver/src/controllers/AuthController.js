import AuthService from "../models/Auth.js";
import { logger } from "../utils/logger.js";
import { normalizeUrl } from "../middleware/originValidator.js";
import jwt from 'jsonwebtoken';
import { parseCookie } from '../utils/cookieUtils.js';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Helper function to extract token from request
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

const checkExistingAuth = (req) => {
  const token = extractToken(req);
  
  if (!token) {
    return { isAuthenticated: false, user: null, token: null };
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return { isAuthenticated: true, user: decoded, token };
  } catch (error) {
    // Token is invalid or expired
    return { isAuthenticated: false, user: null, token: null, error: error.message };
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const applicationUrl = normalizeUrl(req.originInfo?.fullOrigin || req.applicationUrl);
    
    const existingAuth = checkExistingAuth(req);
    
    if (existingAuth.isAuthenticated) {
      logger.info('User already authenticated during login attempt', {
        userId: existingAuth.user.userId,
        email: existingAuth.user.email,
        applicationUrl,
        ip: req.ip
      });
      
      // Check if the authenticated user matches the request
      if (existingAuth.user.email === email) {
        return res.json({
          success: true,
          message: 'Already logged in',
          data: {
            token: existingAuth.token,
            user: {
              userId: existingAuth.user.userId,
              email: existingAuth.user.email,
              username: existingAuth.user.username,
              role: existingAuth.user.role
            },
            expiresIn: process.env.JWT_EXPIRES_IN || '15m'
          }
        });
      } else {
        logger.info('Different user attempting login, proceeding with new authentication', {
          currentUser: existingAuth.user.email,
          requestedUser: email,
          ip: req.ip
        });
      }
    }
    
    const auth = new AuthService.Auth({ email, password, applicationUrl });
    const result = await auth.login();
    if (!result.success) {
      logger.warn('Login failed', {
        email,
        applicationUrl,
        reason: result.message,
        ip: req.ip
      });
      
      return res.status(401).json({
        success: false,
        error: result.error || 'LOGIN_FAILED',
        message: result.message,
        data: result.data
      });
    }
    
    return res.json({
      success: true,
      message: 'Login successful',
      data: result.data
    });
  } catch (error) {
    logger.error('Login error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });
    
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An error occurred during login'
    });
  }
};

export const register = async (req, res) => {
  try {
    const { email, password, username, emailConfig } = req.body; 

    const applicationUrl = normalizeUrl(req.originInfo?.fullOrigin || req.applicationUrl);
    
    const existingAuth = checkExistingAuth(req);
    
    if (existingAuth.isAuthenticated) {
      logger.warn('Authenticated user attempting registration', {
        currentUserId: existingAuth.user.userId,
        currentEmail: existingAuth.user.email,
        requestedEmail: email,
        applicationUrl,
        ip: req.ip
      });
      
      return res.status(400).json({
        success: false,
        error: 'ALREADY_AUTHENTICATED',
        message: 'User is already logged in. Please logout first to register a new account.'
      });
    }

    const auth = new AuthService.Auth({ email, password, username, applicationUrl, emailConfig });
    
    const result = await auth.register();
    if (result.success == false) {
      logger.warn('Registration failed', {
        email,
        username,
        applicationUrl,
        reason: result.message,
        ip: req.ip
      });
      
      return res.status(400).json({
        success: false,
        error: 'REGISTRATION_FAILED',
        message: result.message
      });
    }
    
    return res.status(201).json({
      success: true,
      message: 'Registration successful',
      data: result.data
    });
  } catch (error) {
    logger.error('Registration error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });
    
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An error occurred during registration'
    });
  }
};

export const logout = async (req, res) => {
  try {
    const userId = req.user.userId;

    const auth = new AuthService.Auth({});
    const result = await auth.logout(userId );

    if (!result.success) {
      return res.status(400).json({
        success: false,
        error: 'LOGOUT_FAILED',
        message: result.message
      });
    }
    
    // Clear cookie if it exists
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });
    
    return res.json({
      success: true,
      message: 'Logout successful'
    });
  } catch (error) {
    logger.error('Logout controller error', {
      error: error.message,
      stack: error.stack,
      userId: req.user?.userId,
      ip: req.ip
    });
    
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An error occurred during logout'
    });
  }
};

export const refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        error: 'REFRESH_TOKEN_REQUIRED',
        message: 'Refresh token is required'
      });
    }
    
    const auth = new AuthService.Auth({});
    const result = await auth.refreshToken(refreshToken);
    
    if (!result.success) {
      return res.status(401).json({
        success: false,
        error: 'REFRESH_TOKEN_INVALID',
        message: result.message
      });
    }
    
    return res.json({
      success: true,
      message: result.message,
      data: result.data
    });
  } catch (error) {
    logger.error('Refresh token controller error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });
    
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An error occurred during token refresh'
    });
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({
        success: false,
        error: 'TOKEN_REQUIRED',
        message: 'Verification token is required'
      });
    }
    
    const auth = new AuthService.Auth({});
    const result = await auth.verifyEmail(token);
    
    if (!result.success) {
      return res.status(400).json({
        success: false,
        error: 'VERIFICATION_FAILED',
        message: result.message
      });
    }
    
    return res.json({
      success: true,
      message: result.message,
      data: result.data
    });
  } catch (error) {
    logger.error('Email verification error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });
    
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An error occurred during email verification'
    });
  }
};

export const resendVerificationEmail = async (req, res) => {
  try {
    const { email, emailConfig } = req.body;
    const applicationUrl = normalizeUrl(req.originInfo?.fullOrigin || req.applicationUrl);
    
    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_REQUIRED_FIELDS',
        message: 'Email is required'
      });
    }
    
    const auth = new AuthService.Auth({ email, applicationUrl, emailConfig });
    const result = await auth.resendVerificationEmail();
    
    if (!result.success) {
      return res.status(400).json({
        success: false,
        error: 'RESEND_FAILED',
        message: result.message
      });
    }
    
    return res.json({
      success: true,
      message: result.message
    });
  } catch (error) {
    logger.error('Resend verification email error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });
    
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An error occurred while resending verification email'
    });
  }
};

export const verifyEmailPage = async (req, res) => {
  try {
    const { token } = req.query;
    
    if (token) {
      const user = await prisma.user.findFirst({
        where: {
          emailVerifyToken: token,
          emailVerified: false,
          emailVerifyTokenExpiresAt: {
            gt: new Date()
          }
        },
        select: {
          id: true,
          email: true,
          emailVerified: true
        }
      });
      
      if (!user) {
        const verifiedUser = await prisma.user.findFirst({
          where: {
            emailVerifyToken: token,
            emailVerified: true
          },
          select: {
            email: true
          }
        });
        
        if (verifiedUser) {
          
          return res.status(200).send(`
            <!DOCTYPE html>
            <html>
            <head>
              <title>Email Already Verified</title>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <style>
                body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
                .success { color: #27ae60; }
                .button { display: inline-block; padding: 12px 24px; background: #27ae60; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }
              </style>
            </head>
            <body>
              <h1 class="success">✅ Email Already Verified</h1>
              <p>This email address has already been verified successfully.</p>
              <p>You can now log in to your account.</p>
              <a href="#" class="button" onclick="window.close()">Close</a>
            </body>
            </html>
          `);
        } else {
          return res.status(400).send(`
            <!DOCTYPE html>
            <html>
            <head>
              <title>Invalid Verification Link</title>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <style>
                body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
                .error { color: #e74c3c; }
                .button { display: inline-block; padding: 12px 24px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }
              </style>
            </head>
            <body>
              <h1 class="error">🔗 Invalid or Expired Verification Link</h1>
              <p>This email verification link is either invalid or has expired.</p>
              <p>Email verification links are only valid for 24 hours for security reasons.</p>
              <a href="#" class="button" onclick="window.close()">Close</a>
              <p><small>Need a new verification link? Try logging in - you'll get an option to resend the verification email.</small></p>
            </body>
            </html>
          `);
        }
      }
    } else {
      // No token provided
      return res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Missing Verification Token</title>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
            .error { color: #e74c3c; }
            .button { display: inline-block; padding: 12px 24px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }
          </style>
        </head>
        <body>
          <h1 class="error">🔗 Missing Verification Token</h1>
          <p>This page requires a valid email verification token.</p>
          <p>Please use the link from your verification email.</p>
          <a href="#" class="button" onclick="window.close()">Close</a>
        </body>
        </html>
      `);
    }
    
    const fs = await import('fs');
    const path = await import('path');
    const crypto = await import('crypto');
    const { fileURLToPath } = await import('url');
    
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    
    // Generate a random nonce for the script
    const nonce = crypto.randomBytes(16).toString('base64');
    
    // Set Content Security Policy with the nonce
    res.setHeader('Content-Security-Policy', `script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';`);
    
    const htmlPath = path.join(__dirname, '../views/verify-email.html');
    let html = fs.readFileSync(htmlPath, 'utf8');
    
    // Replace the nonce placeholder with the actual nonce
    html = html.replace('{{NONCE}}', nonce);
    
    // Pre-fill the token in the form
    html = html.replace('{{TOKEN}}', token);
    
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (error) {
    logger.error('Error serving verification page', {
      error: error.message,
      stack: error.stack
    });
    
    res.status(500).send('Internal Server Error');
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const applicationUrl = normalizeUrl(req.originInfo?.fullOrigin || req.applicationUrl);
    
    if (!email ) {
      return res.status(400).json({
        success: false,
          error: 'MISSING_REQUIRED_FIELDS',
          message: 'Email is required'
      });
    }
    
    const auth = new AuthService.Auth({ email, applicationUrl });
    const result = await auth.forgotPassword();
    
    if (!result.success) {
      return res.status(400).json({
        success: false,
        error: 'FORGOT_PASSWORD_FAILED',
        message: result.message
      });
    }
    
    return res.json({
      success: true,
      message: result.message
    });
  } catch (error) {
    logger.error('Forgot password error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });
    
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An error occurred while processing forgot password request'
    });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;
    const applicationUrl = normalizeUrl(req.originInfo?.fullOrigin || req.applicationUrl);
    
    if (!token || !password) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_REQUIRED_FIELDS',
        message: 'Reset token and new password are required'
      });
    }
    
    const auth = new AuthService.Auth({ token, password, applicationUrl });
    const result = await auth.resetPassword();
    
    if (!result.success) {
      return res.status(400).json({
        success: false,
        error: 'RESET_PASSWORD_FAILED',
        message: result.message
      });
    }
    
    return res.json({
      success: true,
      message: result.message,
      data: result.data
    });
  } catch (error) {
    logger.error('Reset password error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });
    
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An error occurred while resetting password'
    });
  }
};

export const checkAuthStatus = async (req, res) => {
  try {
    const existingAuth = checkExistingAuth(req);
    
    if (existingAuth.isAuthenticated) {
      return res.json({
        success: true,
        authenticated: true,
        data: {
          userId: existingAuth.user.userId,
          email: existingAuth.user.email,
          username: existingAuth.user.username,
          role: existingAuth.user.role,
          applicationUrl: existingAuth.user.applicationUrl
        }
      });
    } else {
      return res.json({
        success: true,
        authenticated: false,
        message: existingAuth.error || 'Not authenticated'
      });
    }
  } catch (error) {
    logger.error('Check auth status error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });
    
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An error occurred while checking authentication status'
    });
  }
};

export const resetPasswordPage = async (req, res) => {
  try {
    const { token } = req.query;
    
    if (token) {
      // Check if the token is valid without consuming it
      const user = await prisma.user.findFirst({
        where: {
          passwordResetToken: token,
          passwordResetExpiresAt: {
            gt: new Date()
          }
        },
        select: {
          id: true,
          email: true
        }
      });
      
      if (!user) {
        // Token is invalid or expired - show error page
        return res.status(400).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>Invalid Reset Link</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
              body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
              .error { color: #e74c3c; }
              .button { display: inline-block; padding: 12px 24px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }
            </style>
          </head>
          <body>
            <h1 class="error">🔗 Invalid or Expired Reset Link</h1>
            <p>This password reset link is either invalid or has expired.</p>
            <p>Password reset links are only valid for 1 hour for security reasons.</p>
            <a href="#" class="button" onclick="window.close()">Close</a>
            <p><small>Need a new reset link? Contact support or try the forgot password option again.</small></p>
          </body>
          </html>
        `);
      }
    } else {
      // No token provided
      return res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Missing Reset Token</title>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
            .error { color: #e74c3c; }
            .button { display: inline-block; padding: 12px 24px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }
          </style>
        </head>
        <body>
          <h1 class="error">🔗 Missing Reset Token</h1>
          <p>This page requires a valid password reset token.</p>
          <p>Please use the link from your password reset email.</p>
          <a href="#" class="button" onclick="window.close()">Close</a>
        </body>
        </html>
      `);
    }
    
    const fs = await import('fs');
    const path = await import('path');
    const crypto = await import('crypto');
    const { fileURLToPath } = await import('url');
    
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    
    // Generate a random nonce for the script
    const nonce = crypto.randomBytes(16).toString('base64');
    
    // Set Content Security Policy with the nonce
    res.setHeader('Content-Security-Policy', `script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';`);
    
    const htmlPath = path.join(__dirname, '../views/reset-password.html');
    let html = fs.readFileSync(htmlPath, 'utf8');
    
    // Replace the nonce placeholder with the actual nonce
    html = html.replace('{{NONCE}}', nonce);
    
    // Pre-fill the token in the form
    html = html.replace('{{TOKEN}}', token);
    
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (error) {
    logger.error('Error serving reset password page', {
      error: error.message,
      stack: error.stack
    });
    
    res.status(500).send('Internal Server Error');
  }
};
