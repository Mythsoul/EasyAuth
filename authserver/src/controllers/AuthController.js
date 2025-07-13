import AuthService from "../models/Auth.js";
import { logger } from "../utils/logger.js";
import { normalizeUrl } from "../middleware/originValidator.js";
import { application } from "express";

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const applicationUrl = normalizeUrl(req.applicationUrl);
    
    logger.info('Login attempt', {
      email,
      applicationUrl,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    const auth = new AuthService.Auth({ email, password, applicationUrl });
    const result = await auth.login();
    console.log(result)
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
    
    logger.info('Login successful', {
      email,
      applicationUrl,
      userId: result.data?.id,
      ip: req.ip
    });
    
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
    const applicationUrl = normalizeUrl(req.originInfo?.fullOrigin || application);
    console.log(req.body, applicationUrl);
    logger.info('Registration attempt', {
      email,
      username,
      applicationUrl , 
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    const auth = new AuthService.Auth({ email, password, username, applicationUrl });
    const result = await auth.register();

    if (!result.success) {
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
    
    logger.info('Registration successful', {
      email,
      username,
      applicationUrl,
      userId: result.data?.id,
      ip: req.ip
    });
    
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

