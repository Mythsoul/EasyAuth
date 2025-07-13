import jwt from 'jsonwebtoken';

export const generateToken = (userData) => {
  const payload = {
    userId: userData.id,
    email: userData.email,
    applicationUrl: userData.applicationUrl,
    role: userData.role,
  };

  const options = {
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
  };

  return jwt.sign(payload, process.env.JWT_SECRET, options);
};

