import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { logger } from '../utils/logger.js';
import { PasswordHelper } from '../helpers/password.js';
import { generateToken } from '../helpers/jwtHelper.js';
import { MailHelper } from '../helpers/mailHelper.js';
const prisma = new PrismaClient();

class Auth {
    constructor(formData) {
        this.formData = formData;
    }

    async register() {
        try {
            const { email, password, username, applicationUrl } = this.formData;

            if (!email || !password || !applicationUrl) {
                return {
                    success: false,
                    message: 'Email, password, and application URL are required'
                };
            }

            const existingUser = await prisma.user.findUnique({
                where: {
                    email_applicationUrl: {
                        email: email,
                        applicationUrl: applicationUrl
                    }
                }
            });

            if (existingUser) {
                return {
                    success: false,
                    message: 'User already exists for this application'
                };
            }

           const hashedPassword = await PasswordHelper.hashPassword(password);
            const passwordStrength = PasswordHelper.checkPasswordStrength(password);
            if (!passwordStrength.success) {
                return {
                    success: false,
                    message: passwordStrength.message
                };
            }
            const IsvalidEmail = await MailHelper.checkEmailFormat(email); 
            if (!IsvalidEmail) { 
                return {
                    success: false,
                    message: 'Invalid email format'
                };
            } 

            // Create user
            const user = await prisma.user.create({
                data: {
                    email,
                    password: hashedPassword,
                    username: username || null,
                    applicationUrl,
                    role: 'USER'
                },
                select: {
                    id: true,
                    email: true,
                    username: true,
                    applicationUrl: true,
                    role: true,
                    createdAt: true,
                    emailVerified: true
                }
            });

            // Generate JWT token
         const token = generateToken(user);
            if (!token) {
                return {
                    success: false,
                    message: 'Token generation failed'
                };
            }

            return {
                success: true,
                message: 'Registration successful',
                data: {
                    user,
                    token
                }
            };
        } catch (error) {
            logger.error('Registration error', {
                error: error.message,
                stack: error.stack,
                formData: { ...this.formData, password: '[REDACTED]' }
            });
            return {
                success: false,
                message: 'Registration failed: ' + error.message
            };
        }
    }   

    async login() {
        try {
            const { email, password, applicationUrl } = this.formData;

            if (!email || !password || !applicationUrl) {
                return {
                    success: false,
                    message: 'Email, password, and application URL are required'
                };
            }

            // Find user by email and application URL
            const user = await prisma.user.findUnique({
                where: {
                    email_applicationUrl: {
                        email: email,
                        applicationUrl: applicationUrl
                    }
                }
            });

            if (!user) {
                return {
                    success: false,
                    message: 'Invalid credentials'
                };
            }

            if (!user.isActive) {
                return {
                    success: false,
                    message: 'Account is deactivated'
                };
            }

            const isPasswordValid = PasswordHelper.comparePasswords(password, user.password); 
            if (!isPasswordValid) {
                return {
                    success: false,
                    message: 'Invalid credentials'
                };
            }

            // Update last login
            await prisma.user.update({
                where: { id: user.id },
                data: { lastLogin: new Date() }
            });

            // Generate JWT token
           const token = generateToken(user);
            if (!token) {
                return {
                    success: false,
                    message: 'Token generation failed'
                };
            }


            return {
                success: true,
                message: 'Login successful',
                data: {
                    user: {
                        id: user.id,
                        email: user.email,
                        username: user.username,
                        applicationUrl: user.applicationUrl,
                        role: user.role,
                        emailVerified: user.emailVerified,
                        lastLogin: user.lastLogin
                    },
                    token
                }
            };
        } catch (error) {
            logger.error('Login error', {
                error: error.message,
                stack: error.stack,
                formData: { ...this.formData, password: '[REDACTED]' }
            });

            return {
                success: false,
                message: 'Login failed due to server error'
            };
        }
    }

    async logout() {
        return {
            success: true,
            message: 'Logout successful'
        };
    }
}

export const AuthService = { Auth };
export default AuthService;
