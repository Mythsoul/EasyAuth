import jwt from 'jsonwebtoken';

export const generateToken = (userData) => {
  const payload = {
    userId: userData.id,
    email: userData.email,
    username: userData.username,
    applicationUrl: userData.applicationUrl,
    role: userData.role,
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
  } catch (error) {
    return null;
  }
};

