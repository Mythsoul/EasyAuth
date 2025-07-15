import bcrypt from 'bcrypt'; 
import { logger } from '../utils/logger.js';

class PasswordHelper { 
  static async hashPassword(password) { 
    try { 
      const saltRounds = process.env.SALT_ROUNDS; 
      return bcrypt.hash(password, Number(saltRounds));
    } catch (error) {
      logger.error('Error hashing password:', error);
      throw new Error('Password hashing failed');
    }
  }
  
  static async comparePasswords(password, hashedPassword) {
    try {
      return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
      logger.error('Error comparing passwords:', error);
      throw new Error('Password comparison failed');
    }
  }

  static checkPasswordStrength(password) {
    if (!password) {
      throw new Error('Password is required');
    } 
    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    } 
    let regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/; 
    if (!regex.test(password)) {
      return { 
        success: false,
        message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
      }
    }
    return { success: true };
  }
}

export { PasswordHelper }; 