const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const auth = require('../middleware/auth');
const sendEmail = require('../utils/sendEmail');
const { authRateLimiter } = require('../middleware/auth');

const router = express.Router();

const generateToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRE || '7d' });
};

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
router.post('/register', authRateLimiter, [
    body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Name must be between 2 and 100 characters'),
    body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('role').isIn(['parent', 'educator', 'therapist', 'other']).withMessage('Please select a valid role')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, message: 'Validation failed', errors: errors.array() });
        }

        const { name, email, password, role } = req.body;
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ success: false, message: 'User with this email already exists' });
        }

        const emailVerificationToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = await bcrypt.hash(emailVerificationToken, 10);

        const user = await User.create({ name, email, password, role, emailVerificationToken: hashedToken });

        const token = generateToken(user._id);

        // Send verification email to user
        const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${emailVerificationToken}`;
        await sendEmail({
            to: user.email,
            subject: 'Verify Your Social Pace Support Account',
            template: 'welcome',
            context: { name, verificationUrl }
        });

        // Send notification to support
        await sendEmail({
            to: 'support@socialpacesupport.com',
            subject: 'New User Signup',
            html: `
                <h2>New User Signup</h2>
                <p>Name: ${name}</p>
                <p>Email: ${email}</p>
                <p>Role: ${role}</p>
                <p>Signup Time: ${new Date().toISOString()}</p>
            `
        });

        user.password = undefined;
        res.status(201).json({
            success: true,
            message: 'Account created! Please check your email to verify your account.',
            data: { user: { id: user._id, name, email, role, isEmailVerified: user.isEmailVerified }, token }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
router.post('/login', authRateLimiter, [
    body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
    body('password').exists().withMessage('Password is required')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, message: 'Validation failed', errors: errors.array() });
        }

        const { email, password } = req.body;
        const user = await User.findOne({ email }).select('+password');

        if (!user || !(await user.comparePassword(password)) || !user.isEmailVerified) {
            return res.status(401).json({ success: false, message: 'Invalid credentials or email not verified' });
        }

        const token = generateToken(user._id);
        user.password = undefined;
        res.json({ success: true, data: { user, token } });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// @route   POST /api/auth/verify-email
// @desc    Verify user email
// @access  Public
router.post('/verify-email', [
    body('token').exists().withMessage('Verification token is required')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, message: 'Validation failed', errors: errors.array() });
        }

        const { token } = req.body;
        const user = await User.findOne({ emailVerificationToken: await bcrypt.hash(token, 10) });

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid or expired verification token' });
        }

        user.isEmailVerified = true;
        user.emailVerificationToken = undefined;
        await user.save();

        res.json({ success: true, message: 'Email verified successfully. You can now log in.' });
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// @route   POST /api/auth/forgot-password
// @desc    Send password reset email
// @access  Public
router.post('/forgot-password', authRateLimiter, [
    body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, message: 'Validation failed', errors: errors.array() });
        }

        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.json({ success: true, message: 'If an account with that email exists, a reset link has been sent.' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = await bcrypt.hash(resetToken, 10);
        user.passwordResetToken = hashedToken;
        user.passwordResetExpire = Date.now() + 3600000; // 1 hour
        await user.save({ validateBeforeSave: false });

        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
        await sendEmail({
            to: user.email,
            subject: 'Password Reset Request',
            template: 'passwordReset',
            context: { name: user.name, resetUrl }
        });

        res.json({ success: true, message: 'Password reset email sent.' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// @route   POST /api/auth/reset-password
// @desc    Reset password
// @access  Public
router.post('/reset-password', [
    body('token').exists().withMessage('Reset token is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, message: 'Validation failed', errors: errors.array() });
        }

        const { token, password } = req.body;
        const user = await User.findOne({
            passwordResetToken: await bcrypt.hash(token, 10),
            passwordResetExpire: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid or expired reset token' });
        }

        user.password = password;
        user.passwordResetToken = undefined;
        user.passwordResetExpire = undefined;
        await user.save();

        res.json({ success: true, message: 'Password reset successful. You can now log in.' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// @route   POST /api/auth/logout
// @desc    Logout user
// @access  Private
router.post('/logout', auth, (req, res) => {
    res.json({ success: true, message: 'Logged out successfully' });
});

module.exports = router;