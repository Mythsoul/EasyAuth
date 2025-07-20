import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger.js';
import { PasswordHelper } from '../helpers/password.js';
import { generateToken, generateRefreshToken } from '../helpers/jwtHelper.js';
import { MailHelper } from '../helpers/mailHelper.js';
import TokenBlacklistService from '../services/tokenBlacklist.js';
const prisma = new PrismaClient();

class Auth {
    constructor(formData) {
        this.formData = formData;
    }

    async register() {
        try {
            const { email, password, username, applicationUrl, emailConfig } = this.formData;

            if (!email || !applicationUrl) {
                return {
                    success: false,
                    message: 'Email and application URL are required'
                };
            }
            
            // Password is required for regular registration (not OAuth)
            if (!password) {
                return {
                    success: false,
                    message: 'Password is required for registration'
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

            // Handle email verification if configured
            let emailVerifyToken = null;
            let shouldSendEmail = false;
            
            if (emailConfig && emailConfig.sendVerificationEmail) {
                emailVerifyToken = MailHelper.generateVerificationToken();
                shouldSendEmail = true;
            }

            // Create user
            const user = await prisma.user.create({
                data: {
                    email,
                    password: hashedPassword,
                    username: username || null,
                    applicationUrl,
                    role: 'USER',
                    emailVerifyToken: emailVerifyToken,
                    emailVerifyTokenExpiresAt: shouldSendEmail ? new Date(Date.now() + 24 * 60 * 60 * 1000) : null, // 24 hours
                    emailVerified: !shouldSendEmail 
                },
                select: {
                    id: true,
                    email: true,
                    username: true,
                    applicationUrl: true,
                    role: true,
                    createdAt: true,
                    emailVerified: true,
                    emailVerifyToken: true
                }
            });

            // Generate JWT token
         const token = generateToken(user);
         const refreshToken = generateRefreshToken();
            if (!token || !refreshToken) {
                return {
                    success: false,
                    message: 'Token generation failed'
                };
            }
            // Store refresh token in database
            await prisma.refreshToken.create({
                data: {
                    token: refreshToken,
                    userId: user.id,
                    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
                }
            });
            
            if (!token) {
                return {
                    success: false,
                    message: 'Token generation failed'
                };
            }

            let emailResult = null;
            if (shouldSendEmail) {
                emailResult = await MailHelper.sendVerificationEmail(
                    user.email,
                    user.emailVerifyToken,
                    applicationUrl
                );
            }

            // Prepare response data
            const responseData = {
                user: {
                    id: user.id,
                    email: user.email,
                    username: user.username,
                    applicationUrl: user.applicationUrl,
                    role: user.role,
                    emailVerified: user.emailVerified,
                    createdAt: user.createdAt
                },
                token
            };

            // Add email info if verification email was sent
            if (shouldSendEmail) {
                responseData.emailVerification = {
                    sent: emailResult?.success || false,
                    message: emailResult?.message || 'Email sending status unknown',
                    required: emailConfig.requireEmailVerification || false
                };
            }

            return {
                success: true,
                message: shouldSendEmail 
                    ? 'Registration successful. Please check your email for verification instructions.'
                    : 'Registration successful',
                data: responseData
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

            // Check if user has a password (regular login) or is OAuth user
            if (!user.password) {
                return {
                    success: false,
                    error: 'OAUTH_USER_LOGIN_REQUIRED',
                    message: 'This account uses OAuth login. Please use your OAuth provider to sign in.'
                };
            }

            const isPasswordValid = await PasswordHelper.comparePasswords(password, user.password);
            if (!isPasswordValid) {
                return {
                    success: false,
                    message: 'Invalid credentials'
                };
            }

            // Check if email verification is required and user is not verified
            if (!user.emailVerified && user.emailVerifyToken) {
                return {
                    success: false,
                    error: 'EMAIL_NOT_VERIFIED',
                    message: 'Please verify your email address before logging in',
                    data: {
                        emailVerified: false,
                        canResendEmail: true
                    }
                };
            }

            // Update last login
            await prisma.user.update({
                where: { id: user.id },
                data: { lastLogin: new Date() }
            });

            // Generate access token and refresh token
            const accessToken = generateToken(user);
            const refreshToken = generateRefreshToken();
            
            if (!accessToken || !refreshToken) {
                return {
                    success: false,
                    message: 'Token generation failed'
                };
            }

            // Store refresh token in database
            await prisma.refreshToken.create({
                data: {
                    token: refreshToken,
                    userId: user.id,
                    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
                }
            });

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
                    token: accessToken,
                    refreshToken
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

    async logout(userId ) {
        try {
            // Clear any existing sessions for this user
            await prisma.session.deleteMany({
                where: {
                    userId: userId
                }
            });

            // Clear refresh tokens for this user
            await prisma.refreshToken.deleteMany({
                where: {
                    userId: userId
                }
            });

            // Blacklist the token  
             await prisma.tokenBlacklist.create({ 
                data: {
                    userId: userId,
                    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), 
                    jti : generateToken({ userId })
                }
             })

            logger.info('User logged out successfully', {
                userId,
                timestamp: new Date()
            });

            return {
                success: true,
                message: 'Logout successful'
            };
        } catch (error) {
            logger.error('Logout error', {
                error: error.message,
                stack: error.stack,
                userId
            });
            return {
                success: false,
                message: 'Logout failed due to server error'
            };
        }
    }

    async refreshToken(refreshToken) {
        try {
            if (!refreshToken) {
                return {
                    success: false,
                    message: 'Refresh token is required'
                };
            }

            // Find refresh token in database
            const storedToken = await prisma.refreshToken.findUnique({
                where: { token: refreshToken },
                include: { user: true }
            });

            if (!storedToken) {
                return {
                    success: false,
                    message: 'Invalid refresh token'
                };
            }

            // Check if token is expired
            if (storedToken.expiresAt < new Date()) {
                // Remove expired token
                await prisma.refreshToken.delete({
                    where: { id: storedToken.id }
                });
                return {
                    success: false,
                    message: 'Refresh token expired'
                };
            }

            // Generate new access token
            const newAccessToken = generateToken(storedToken.user);
            
            if (!newAccessToken) {
                return {
                    success: false,
                    message: 'Token generation failed'
                };
            }

            return {
                success: true,
                message: 'Token refreshed successfully',
                data: {
                    token: newAccessToken,
                    user: {
                        id: storedToken.user.id,
                        email: storedToken.user.email,
                        username: storedToken.user.username,
                        role: storedToken.user.role
                    }
                }
            };
        } catch (error) {
            logger.error('Refresh token error', {
                error: error.message,
                stack: error.stack
            });
            return {
                success: false,
                message: 'Token refresh failed due to server error'
            };
        }
    }

    async verifyEmail(token) {
        try {
            if (!token) {
                return {
                    success: false,
                    message: 'Verification token is required'
                };
            }

            const user = await prisma.user.findFirst({
                where: {
                    emailVerifyToken: token,
                    emailVerified: false
                }
            });

            if (!user) {
                return {
                    success: false,
                    message: 'Invalid or expired verification token'
                };
            }

            // Check if token is expired
            if (user.emailVerifyTokenExpiresAt && user.emailVerifyTokenExpiresAt < new Date()) {
                return {
                    success: false,
                    message: 'Verification token has expired. Please request a new one.'
                };
            }

            // Update user to mark email as verified
            const updatedUser = await prisma.user.update({
                where: { id: user.id },
                data: {
                    emailVerified: true,
                    emailVerifyToken: null, 
                    emailVerifyTokenExpiresAt: null, 
                },
                select: {
                    id: true,
                    email: true,
                    username: true,
                    applicationUrl: true,
                    role: true,
                    emailVerified: true
                }
            });

            logger.info('Email verified successfully', {
                userId: updatedUser.id,
                email: updatedUser.email,
                applicationUrl: updatedUser.applicationUrl
            });

            return {
                success: true,
                message: 'Email verified successfully',
                data: {
                    user: updatedUser
                }
            };
        } catch (error) {
            logger.error('Email verification error', {
                error: error.message,
                stack: error.stack,
                token: token ? `${token.substring(0, 10)}...` : 'null'
            });
            return {
                success: false,
                message: 'Email verification failed due to server error'
            };
        }
    }

    async resendVerificationEmail() {
        try {
            const { email, applicationUrl } = this.formData;

            if (!email || !applicationUrl) {
                return {
                    success: false,
                    message: 'Email and application URL are required'
                };
            }

            // Validate email configuration

    

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
                    message: 'User not found'
                };
            }

            if (user.emailVerified) {
                return {
                    success: false,
                    message: 'Email is already verified'
                };
            }

            // Generate new verification token
            const newToken = MailHelper.generateVerificationToken();
            
            await prisma.user.update({
                where: { id: user.id },
                data: {
                    emailVerifyToken: newToken,
                    emailVerifyTokenExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
                }
            });

            const emailResult = await MailHelper.sendVerificationEmail(
                user.email,
                newToken,
                applicationUrl
            );

            if (!emailResult.success) {
                return {
                    success: false,
                    message: emailResult.message
                };
            }

            logger.info('Verification email resent', {
                userId: user.id,
                email: user.email,
                applicationUrl: user.applicationUrl
            });

            return {
                success: true,
                message: 'Verification email sent successfully'
            };
        } catch (error) {
            logger.error('Resend verification email error', {
                error: error.message,
                stack: error.stack,
                formData: { ...this.formData, emailConfig: '[REDACTED]' }
            });
            return {
                success: false,
                message: 'Failed to resend verification email due to server error'
            };
        }
    }

    async forgotPassword() {
        try {
            const { email, applicationUrl } = this.formData;

            if (!email || !applicationUrl) {
                return {
                    success: false,
                    message: 'Email and application URL are required'
                };
            }


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
                    success: true,
                    message: 'If an account with this email exists, you will receive a password reset link shortly.'
                };
            }

            if (!user.isActive) {
                return {
                    success: false,
                    message: 'Account is deactivated'
                };
            }
           
            
            const resetToken = MailHelper.generatePasswordResetToken();
            
            await prisma.user.update({
                where: { id: user.id },
                data: {
                    passwordResetToken: resetToken,
                    passwordResetExpiresAt: new Date(Date.now() + 60 * 60 * 1000) // 1 hour
                }
            });

            const emailResult = await MailHelper.sendPasswordResetEmail(
                user.email,
                resetToken,
                applicationUrl
            );

            if (!emailResult.success) {
                logger.error('Failed to send password reset email', {
                    userId: user.id,
                    email: user.email,
                    error: emailResult.message
                });
                return {
                    success: false,
                    message: emailResult.message
                };
            }

            logger.info('Password reset email sent', {
                userId: user.id,
                email: user.email,
                applicationUrl: user.applicationUrl
            });

            return {
                success: true,
                message: 'Password reset instructions have been sent to your email address.'
            };
        } catch (error) {
            logger.error('Forgot password error', {
                error: error.message,
                stack: error.stack,
                formData: { ...this.formData, emailConfig: '[REDACTED]' }
            });
            return {
                success: false,
                message: 'Failed to process forgot password request due to server error'
            };
        }
    }

    async resetPassword() {
        try {
            const { token, password } = this.formData;
            
            if (!token || !password) {
                return {
                    success: false,
                    message: 'Reset token and new password are required'
                };
            }

            // Validate password strength
            const passwordStrength = PasswordHelper.checkPasswordStrength(password);
            if (!passwordStrength.success) {
                return {
                    success: false,
                    message: passwordStrength.message
                };
            }

            const user = await prisma.user.findFirst({
                where: {
                    passwordResetToken: token,
                    passwordResetExpiresAt: {
                        gt: new Date()
                    }
                }
            });

            if (!user) {
                return {
                    success: false,
                    message: 'Invalid or expired reset token'
                };
            }

            if (!user.isActive) {
                return {
                    success: false,
                    message: 'Account is deactivated'
                };
            }

            // Hash the new password
            const hashedPassword = await PasswordHelper.hashPassword(password);

            // Update user's password and clear reset token
            const updatedUser = await prisma.user.update({
                where: { id: user.id },
                data: {
                    password: hashedPassword,
                    passwordResetToken: null,
                    passwordResetExpiresAt: null,
                    updatedAt: new Date()
                },
                select: {
                    id: true,
                    email: true,
                    username: true,
                    applicationUrl: true,
                    role: true,
                    emailVerified: true
                }
            });

            // Clear all refresh tokens and sessions
            await prisma.refreshToken.deleteMany({
                where: {
                    userId: user.id
                }
            });

            await prisma.session.deleteMany({
                where: {
                    userId: user.id
                }
            });

            await TokenBlacklistService.blacklistAllUserTokens(user.id, 'password_reset');

            logger.info('Password reset successful - all tokens invalidated', {
                userId: updatedUser.id,
                email: updatedUser.email,
                applicationUrl: updatedUser.applicationUrl
            });

            return {
                success: true,
                message: 'Password has been reset successfully. Please log in with your new password.',
                data: {
                    user: updatedUser
                }
            };
        } catch (error) {
            logger.error('Reset password error', {
                error: error.message,
                stack: error.stack,
                formData: { ...this.formData, password: '[REDACTED]' }
            });
            return {
                success: false,
                message: 'Failed to reset password due to server error'
            };
        }
    }
}

export const AuthService = { Auth };
export default AuthService;
