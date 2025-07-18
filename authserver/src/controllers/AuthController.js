import AuthService from "../models/Auth.js";
import { logger } from "../utils/logger.js";
import { normalizeUrl } from "../middleware/originValidator.js";

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const applicationUrl = normalizeUrl(req.originInfo?.fullOrigin || req.applicationUrl);
    
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
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
    
    const auth = new AuthService.Auth({});
    const result = await auth.logout(userId, token);
    
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
    
    if (!email || !emailConfig) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_REQUIRED_FIELDS',
        message: 'Email and email configuration are required'
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

export const resetPasswordPage = async (req, res) => {
  try {
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
