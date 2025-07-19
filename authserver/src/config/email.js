import nodemailer from 'nodemailer';
import { logger } from '../utils/logger.js';

class EmailConfig {
    constructor() {
        this.transporter = null;
       
    }

    initTransporter() {
        try {
            if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
                logger.warn('Email configuration missing. Email sending will be disabled.');
                return;
            }

            this.transporter = nodemailer.createTransport({
                host: process.env.SMTP_HOST,
                port: parseInt(process.env.SMTP_PORT) || 587,
                secure: false, // Use STARTTLS
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS
                }
            });

            // Verify connection
            this.transporter.verify((error) => {
                if (error) {            
                    logger.error('Email transporter verification failed', { error: error.message });
                } else {
                    logger.info('Email transporter ready');
                }
            });
        } catch (error) {
            logger.error('Failed to initialize email transporter', { error: error.message });
        }
    }

    getTransporter() {
        if (!this.transporter) {
            this.initTransporter();
        }
        return this.transporter;
    }

    isConfigured() {
        if (!this.transporter) {
            this.initTransporter();
        }
        return this.transporter !== null;
    }

    static get fromEmail() {
        return process.env.SMTP_FROM;
    }

    static get fromName() {
        return process.env.SMTP_FROM_NAME || 'EasyAuth Server';
    }
}

// Create singleton instance
const emailConfig = new EmailConfig();

export default emailConfig;
export { EmailConfig };
