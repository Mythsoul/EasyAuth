import crypto from 'crypto';
import { logger } from '../utils/logger.js';
import emailConfig from '../config/email.js';

class MailHelper { 
    constructor (mailService) {
        this.mailService = mailService;
    }
    
    static async checkEmailFormat (email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            throw new Error('Invalid email format');
        }
        return true;
    }

    // Generate email verification token
    static generateVerificationToken() {
        return crypto.randomBytes(32).toString('hex');
    }

    // Generate password reset token
    static generatePasswordResetToken() {
        return crypto.randomBytes(32).toString('hex');
    }

    static async sendPasswordResetEmail( userEmail, resetToken, applicationUrl) {
        try {
            // Check if server email is configured
            if (!emailConfig.isConfigured()) {
                logger.warn('Server email not configured, cannot send password reset email');
                return { success: false, message: 'Email service not configured' };
            }

            const transporter = emailConfig.getTransporter();

            const serverUrl = process.env.SERVER_URL || 'http://localhost:3000/api/v1';
            const resetUrl = `${serverUrl}/reset-password?token=${resetToken}&redirect=${encodeURIComponent(applicationUrl)}`;

            const appName = this.extractAppNameFromUrl(applicationUrl);

            const mailOptions = {
                from: `"${emailConfig.fromName}" <${emailConfig.fromEmail}>`,
                to: userEmail,
                subject: `Password Reset Request from ${appName}`,
                html: this.getPasswordResetEmailTemplate(resetUrl, appName),
                text: `We have received a request to reset your password for ${appName}. Please follow this link to reset your password: ${resetUrl}`
            };

            await transporter.sendMail(mailOptions);
            logger.info('Password reset email sent', { email: userEmail, applicationUrl, appName });

            return { success: true, message: 'Password reset email sent successfully' };
        } catch (error) {
            logger.error('Failed to send password reset email', { 
                error: error.message, 
                email: userEmail, 
                applicationUrl 
            });
            return { success: false, message: 'Failed to send password reset email' };
        }
    }

    // Send verification email using server's email service
    static async sendVerificationEmail(userEmail, verificationToken, applicationUrl) {
        try {
            // Check if server email is configured
            if (!emailConfig.isConfigured()) {
                logger.warn('Server email not configured, cannot send verification email');
                return { success: false, message: 'Email service not configured' };
            }

            const transporter = emailConfig.getTransporter();
            
            
            const serverUrl = process.env.SERVER_URL || 'http://localhost:3000/api/v1';
            const verificationUrl = `${serverUrl}/verify-email?token=${verificationToken}&redirect=${encodeURIComponent(applicationUrl)}`;
            
            // Use client's app name for personalization, fallback to domain
            const appName = this.extractAppNameFromUrl(applicationUrl);
            
            const mailOptions = {
                from: `"${emailConfig.fromName}" <${emailConfig.fromEmail}>`,
                to: userEmail,
                subject: `Verify your email address for ${appName}`,
                html: this.getVerificationEmailTemplate(verificationUrl, appName),
                text: `Welcome to ${appName}! Please verify your email address by clicking this link: ${verificationUrl}`
            };

            await transporter.sendMail(mailOptions);
            logger.info('Verification email sent', { email: userEmail, applicationUrl, appName });
            
            return { success: true, message: 'Verification email sent successfully' };
        } catch (error) {
            logger.error('Failed to send verification email', { 
                error: error.message, 
                email: userEmail, 
                applicationUrl 
            });
            return { success: false, message: 'Failed to send verification email' };
        }
    }

    // Replace template variables
    static replaceTemplateVariables(template, variables) {
        let result = template;
        Object.entries(variables).forEach(([key, value]) => {
            const regex = new RegExp(`{{${key}}}`, 'g');
            result = result.replace(regex, value);
        });
        return result;
    }

    // Extract app name from URL
    static extractAppNameFromUrl(url) {
        try {
            const urlObj = new globalThis.URL(url);
            const hostname = urlObj.hostname;
            
            // Remove common subdomains
            const cleanHostname = hostname.replace(/^(www|app|api)\./i, '');
            
            // Extract the main domain name
            const parts = cleanHostname.split('.');
            const mainDomain = parts.length > 1 ? parts[0] : cleanHostname;
            
            // Capitalize first letter
            return mainDomain.charAt(0).toUpperCase() + mainDomain.slice(1);
        } catch {
            return 'Your App';
        }
    }

    // Professional verification email template
    static getVerificationEmailTemplate(verificationUrl, appName) {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Verify Your Email Address</title>
            </head>
            <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
                <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 0;">
                    <!-- Header -->
                    <div style="background-color: #007bff; padding: 40px 20px; text-align: center;">
                        <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: bold;">
                            Welcome to ${appName}!
                        </h1>
                    </div>
                    
                    <!-- Content -->
                    <div style="padding: 40px 20px;">
                        <h2 style="color: #333333; margin: 0 0 20px 0; font-size: 24px;">
                            Please verify your email address
                        </h2>
                        
                        <p style="color: #666666; font-size: 16px; line-height: 1.6; margin: 0 0 30px 0;">
                            Thank you for signing up for ${appName}! To complete your registration and secure your account, please verify your email address by clicking the button below.
                        </p>
                        
                        <!-- CTA Button -->
                        <div style="text-align: center; margin: 40px 0;">
                            <a href="${verificationUrl}" style="display: inline-block; background-color: #007bff; color: #ffffff; padding: 16px 32px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; text-align: center; margin: 0 auto;">
                                Verify Email Address
                            </a>
                        </div>
                        
                        <p style="color: #666666; font-size: 14px; line-height: 1.6; margin: 30px 0 0 0;">
                            If the button above doesn't work, you can copy and paste this link into your browser:
                        </p>
                        
                        <p style="color: #007bff; font-size: 14px; word-break: break-all; margin: 10px 0 30px 0;">
                            ${verificationUrl}
                        </p>
                        
                        <div style="border-top: 1px solid #eeeeee; padding-top: 30px; margin-top: 40px;">
                            <p style="color: #999999; font-size: 14px; line-height: 1.6; margin: 0;">
                                <strong>Security note:</strong> If you didn't create an account with ${appName}, please ignore this email. Your email address will not be added to our system.
                            </p>
                        </div>
                    </div>
                    
                    <!-- Footer -->
                    <div style="background-color: #f8f9fa; padding: 20px; text-align: center; border-top: 1px solid #eeeeee;">
                        <p style="color: #999999; font-size: 12px; margin: 0;">
                            This email was sent by EasyAuth Server on behalf of ${appName}
                        </p>
                    </div>
                </div>
            </body>
            </html>
        `;
    }

    // Professional password reset email template
    static getPasswordResetEmailTemplate(resetUrl, appName) {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Reset Your Password</title>
            </head>
            <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
                <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 0;">
                    <!-- Header -->
                    <div style="background-color: #dc3545; padding: 40px 20px; text-align: center;">
                        <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: bold;">
                            Password Reset Request
                        </h1>
                    </div>
                    
                    <!-- Content -->
                    <div style="padding: 40px 20px;">
                        <h2 style="color: #333333; margin: 0 0 20px 0; font-size: 24px;">
                            Reset your password for ${appName}
                        </h2>
                        
                        <p style="color: #666666; font-size: 16px; line-height: 1.6; margin: 0 0 30px 0;">
                            We received a request to reset your password for your ${appName} account. If you made this request, please click the button below to reset your password.
                        </p>
                        
                        <!-- CTA Button -->
                        <div style="text-align: center; margin: 40px 0;">
                            <a href="${resetUrl}" style="display: inline-block; background-color: #dc3545; color: #ffffff; padding: 16px 32px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; text-align: center; margin: 0 auto;">
                                Reset Password
                            </a>
                        </div>
                        
                        <p style="color: #666666; font-size: 14px; line-height: 1.6; margin: 30px 0 0 0;">
                            If the button above doesn't work, you can copy and paste this link into your browser:
                        </p>
                        
                        <p style="color: #dc3545; font-size: 14px; word-break: break-all; margin: 10px 0 30px 0;">
                            ${resetUrl}
                        </p>
                        
                        <div style="border-top: 1px solid #eeeeee; padding-top: 30px; margin-top: 40px;">
                            <p style="color: #999999; font-size: 14px; line-height: 1.6; margin: 0;">
                                <strong>Security note:</strong> This password reset link will expire in 1 hour. If you didn't request a password reset, please ignore this email or contact support if you have concerns.
                            </p>
                        </div>
                    </div>
                    
                    <!-- Footer -->
                    <div style="background-color: #f8f9fa; padding: 20px; text-align: center; border-top: 1px solid #eeeeee;">
                        <p style="color: #999999; font-size: 12px; margin: 0;">
                            This email was sent by EasyAuth Server on behalf of ${appName}
                        </p>
                    </div>
                </div>
            </body>
            </html>
        `;
    }

    
}

export {MailHelper};
