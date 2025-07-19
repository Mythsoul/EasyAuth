import jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';

export const generateToken = (userData) => {
  // Generate unique JWT ID for token blacklisting
  const jti = randomBytes(16).toString('hex');
  
  const payload = {
    userId: userData.id,
    email: userData.email,
    username: userData.username,
    applicationUrl: userData.applicationUrl,
    role: userData.role,
    jti: jti // Add unique JWT ID
  };

  const options = {
    expiresIn: process.env.JWT_EXPIRES_IN || '15m', 
  };

  return jwt.sign(payload, process.env.JWT_SECRET, options);
};

export const generateRefreshToken = () => {
  return jwt.sign(
    { 
      type: 'refresh',
      jti: Math.random().toString(36).substr(2, 9)
    },
    process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
  );
};

export const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET);
  } catch {
    return null;
  }
};

