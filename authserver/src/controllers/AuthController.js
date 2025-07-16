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
        error: 'LOGIN_FAILED',
        message: result.message
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
    const { email, password, username } = req.body;
    const applicationUrl = normalizeUrl(req.originInfo?.fullOrigin || req.applicationUrl);

    const auth = new AuthService.Auth({ email, password, username, applicationUrl });
    
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


