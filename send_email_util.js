const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs').promises;

const createTransporter = () => {
    return nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        secure: process.env.EMAIL_SECURE === 'true', // Use env var for flexibility
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });
};

const templates = {
    welcome: {
        subject: 'Verify Your Social Pace Support Account',
        html: `
            <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="background: linear-gradient(135deg, #4a7c8a, #6b9aa8); padding: 40px 30px; text-align: center;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">Verify Your Account</h1>
                </div>
                <div style="padding: 30px; background: white;">
                    <h2 style="color: #4a7c8a;">Hi {{name}},</h2>
                    <p style="font-size: 16px; margin-bottom: 20px;">Thank you for joining Social Pace Support! Please verify your email by clicking the button below:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{{verificationUrl}}" style="background: #4a7c8a; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: 600;">Verify Email</a>
                    </div>
                    <p style="font-size: 14px; color: #666;">If the button doesn’t work, copy this link: <a href="{{verificationUrl}}" style="color: #4a7c8a;">{{verificationUrl}}</a></p>
                </div>
                <div style="background: #f8f9fa; padding: 20px 30px; text-align: center; font-size: 14px; color: #666;">
                    <p style="margin: 0;">The Social Pace Support Team</p>
                </div>
            </div>
        `
    },
    passwordReset: {
        subject: 'Password Reset Request',
        html: `
            <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="background: linear-gradient(135deg, #4a7c8a, #6b9aa8); padding: 40px 30px; text-align: center;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">Reset Your Password</h1>
                </div>
                <div style="padding: 30px; background: white;">
                    <h2 style="color: #4a7c8a;">Hi {{name}},</h2>
                    <p style="font-size: 16px; margin-bottom: 20px;">We received a request to reset your password. Click below to set a new one:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{{resetUrl}}" style="background: #4a7c8a; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: 600;">Reset Password</a>
                    </div>
                    <p style="font-size: 14px; color: #666;">This link expires in 1 hour. If you didn’t request this, ignore this email.</p>
                </div>
                <div style="background: #f8f9fa; padding: 20px 30px; text-align: center; font-size: 14px; color: #666;">
                    <p style="margin: 0;">The Social Pace Support Team</p>
                </div>
            </div>
        `
    }
};

const renderTemplate = (template, context = {}) => {
    let html = templates[template].html;
    for (const key in context) {
        html = html.replace(new RegExp(`{{${key}}}`, 'g'), context[key] || '');
    }
    return { subject: templates[template].subject, html };
};

const sendEmail = async (options) => {
    try {
        const transporter = createTransporter();
        let { to, subject, html, text, template, context } = options;

        if (template && templates[template]) {
            const rendered = renderTemplate(template, context);
            subject = subject || rendered.subject;
            html = rendered.html;
        }

        const mailOptions = {
            from: `Social Pace Support <${process.env.FROM_EMAIL || process.env.EMAIL_USER}>`,
            to,
            subject,
            html,
            text: text || html?.replace(/<[^>]*>/g, '')
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('✉️ Email sent:', { to, subject, messageId: info.messageId });
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('❌ Email sending failed:', error);
        throw error;
    }
};

const sendBulkEmail = async (subscribers, template, context = {}) => {
    const results = [];
    const batchSize = 10;

    for (let i = 0; i < subscribers.length; i += batchSize) {
        const batch = subscribers.slice(i, i + batchSize);
        const batchPromises = batch.map(async (subscriber) => {
            try {
                const personalizedContext = {
                    ...context,
                    email: subscriber.email,
                    unsubscribeUrl: `${process.env.FRONTEND_URL}/unsubscribe?token=${subscriber.unsubscribeToken}`
                };
                await sendEmail({ to: subscriber.email, template, context: personalizedContext });
                return { email: subscriber.email, success: true };
            } catch (error) {
                console.error(`Failed to send to ${subscriber.email}:`, error.message);
                return { email: subscriber.email, success: false, error: error.message };
            }
        });
        results.push(...await Promise.all(batchPromises));
        if (i + batchSize < subscribers.length) await new Promise(resolve => setTimeout(resolve, 1000));
    }

    const { successful, failed } = results.reduce((acc, r) => ({
        successful: acc.successful + (r.success ? 1 : 0),
        failed: acc.failed + (r.success ? 0 : 1)
    }), { successful: 0, failed: 0 });

    console.log(`📧 Bulk email: ${successful} sent, ${failed} failed`);
    return { total: results.length, successful, failed, results };
};

module.exports = { sendEmail, sendBulkEmail, renderTemplate };