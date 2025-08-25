const express = require('express');
const { body, validationResult } = require('express-validator');
const EmailSubscription = require('../models/EmailSubscription');
const { auth, optionalAuth } = require('../middleware/auth');
const sendEmail = require('../utils/sendEmail');
const crypto = require('crypto');

const router = express.Router();

// @route   POST /api/subscriptions/newsletter
// @desc    Subscribe to newsletter
// @access  Public
router.post('/newsletter', [
    body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, message: 'Validation failed', errors: errors.array() });
        }

        const { email } = req.body;
        const existingSubscription = await EmailSubscription.findOne({ email });

        if (existingSubscription) {
            if (existingSubscription.isActive) {
                return res.status(400).json({ success: false, message: 'Already subscribed' });
            } else {
                existingSubscription.isActive = true;
                existingSubscription.subscribedAt = new Date();
                existingSubscription.unsubscribedAt = null;
                existingSubscription.unsubscribeToken = crypto.randomBytes(32).toString('hex');
                await existingSubscription.save();
                await sendEmail({ to: email, subject: 'Welcome Back!', template: 'newsletterWelcomeBack', context: { email, unsubscribeUrl: `${process.env.FRONTEND_URL}/unsubscribe?token=${existingSubscription.unsubscribeToken}` } });
                return res.json({ success: true, message: 'Welcome back! Subscribed.' });
            }
        }

        const unsubscribeToken = crypto.randomBytes(32).toString('hex');
        const subscription = await EmailSubscription.create({ email, source: 'website_footer', unsubscribeToken });
        await sendEmail({ to: email, subject: 'Welcome to Newsletter!', template: 'newsletterWelcome', context: { email, unsubscribeUrl: `${process.env.FRONTEND_URL}/unsubscribe?token=${unsubscribeToken}` } });

        res.status(201).json({ success: true, message: 'Subscribed! Check your email.' });
    } catch (error) {
        console.error('Newsletter subscription error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// @route   POST /api/subscriptions/unsubscribe
// @desc    Unsubscribe from newsletter
// @access  Public
router.post('/unsubscribe', [
    body('token').exists().withMessage('Unsubscribe token is required')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, message: 'Validation failed', errors: errors.array() });
        }

        const { token } = req.body;
        const subscription = await EmailSubscription.findOne({ unsubscribeToken: token });

        if (!subscription) {
            return res.status(400).json({ success: false, message: 'Invalid unsubscribe token' });
        }

        await subscription.unsubscribe();
        res.json({ success: true, message: 'Unsubscribed successfully' });
    } catch (error) {
        console.error('Unsubscribe error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// @route   GET /api/subscriptions/preferences
// @desc    Get user subscription preferences
// @access  Private
router.get('/preferences', auth, async (req, res) => {
    try {
        res.json({ success: true, data: { preferences: req.user.preferences } });
    } catch (error) {
        console.error('Get preferences error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// @route   PUT /api/subscriptions/preferences
// @desc    Update subscription preferences
// @access  Private
router.put('/preferences', auth, [
    body('emailNotifications').optional().isBoolean(),
    body('marketingEmails').optional().isBoolean(),
    body('courseReminders').optional().isBoolean()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, message: 'Invalid preferences', errors: errors.array() });
        }

        const { emailNotifications, marketingEmails, courseReminders } = req.body;
        const user = req.user;

        if (emailNotifications !== undefined) user.preferences.emailNotifications = emailNotifications;
        if (marketingEmails !== undefined) user.preferences.marketingEmails = marketingEmails;
        if (courseReminders !== undefined) user.preferences.courseReminders = courseReminders;

        await user.save({ validateBeforeSave: false });
        res.json({ success: true, message: 'Preferences updated', data: { preferences: user.preferences } });
    } catch (error) {
        console.error('Update preferences error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// @route   GET /api/subscriptions/stats
// @desc    Get subscription statistics
// @access  Private (Admin)
router.get('/stats', auth, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied' });
        }

        const total = await EmailSubscription.countDocuments();
        const active = await EmailSubscription.countDocuments({ isActive: true });
        const recent = await EmailSubscription.countDocuments({ subscribedAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } });
        const sourceStats = await EmailSubscription.aggregate([{ $match: { isActive: true } }, { $group: { _id: '$source', count: { $sum: 1 } } }, { $sort: { count: -1 } }]);

        res.json({ success: true, data: { total, active, inactive: total - active, recent, sources: sourceStats } });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

module.exports = router;